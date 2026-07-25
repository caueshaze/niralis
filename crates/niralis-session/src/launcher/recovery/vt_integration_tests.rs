//! Root-only tests for the real VT ioctl.  They are deliberately ignored: the
//! shell runner performs the production-session preflight before invoking this
//! libtest harness as root.
use super::*;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::process::Command;

#[derive(serde::Deserialize)]
struct HolderMessage {
    kind: String,
    pid: u32,
    starttime: u64,
    uid: u32,
    fd: i32,
    executable_device: u64,
    executable_inode: u64,
    device_major: u32,
    device_minor: u32,
    cgroup: Option<String>,
}

fn helper() -> String {
    std::env::var("NIRALIS_VT_FIXTURE_HELPER").expect("root runner must provide VT helper")
}

fn candidate_vt() -> u32 {
    let active = inspect_vt_busy(1, &[])
        .observed_active_vt
        .expect("active VT required");
    (1..=63)
        .find(|candidate| {
            *candidate != active
                && std::path::Path::new(&format!("/dev/tty{candidate}")).exists()
                && matches!(
                    inspect_vt_busy(*candidate, &[]).classification,
                    crate::VtBusyClassification::KernelBusyUnattributed
                )
        })
        .expect("a fully inspectable, non-foreground sacrificial VT is required")
}
include!("vt_integration_recovery_admin.rs");

#[test]
#[ignore = "requires the root-only sacrificial VT runner"]
fn real_vt_busy_provenance_identifies_exact_holder() {
    let target = candidate_vt();
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let socket = directory.path().join("ready.sock");
    let listener = UnixListener::bind(&socket).expect("ready listener");
    let eventfd = unsafe { libc::eventfd(0, 0) };
    assert!(eventfd >= 0, "eventfd");
    let eventfd = unsafe { OwnedFd::from_raw_fd(eventfd) };
    let mut child = Command::new(helper())
        .arg("--target-vt")
        .arg(target.to_string())
        .arg("--ready-socket")
        .arg(&socket)
        .arg("--release-eventfd")
        .arg(eventfd.as_raw_fd().to_string())
        .spawn()
        .expect("start VT holder");
    let (stream, _) = listener.accept().expect("holder ready connection");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("holder ready message");
    assert!(line.len() <= 1024, "bounded helper message");
    let ready: HolderMessage = serde_json::from_str(&line).expect("typed helper ready");
    assert_eq!(ready.kind, "Ready");
    let result = disallocate_virtual_terminal_once(target);
    assert!(
        matches!(result, Err(SupervisorRecoveryError::VtDisallocateBusy)),
        "holder must cause EBUSY: {result:?}"
    );
    let provenance = inspect_vt_busy(target, &[]);
    assert_eq!(
        provenance.classification,
        crate::VtBusyClassification::VisibleUserspaceHolder
    );
    let holder = provenance
        .visible_holders
        .iter()
        .find(|value| value.pid == ready.pid)
        .expect("exact holder");
    assert_eq!(holder.starttime, ready.starttime);
    assert_eq!(holder.uid, ready.uid);
    assert_eq!(holder.fd as i32, ready.fd);
    assert_eq!(
        holder
            .executable
            .as_ref()
            .map(|value| (value.device, value.inode)),
        Some((ready.executable_device, ready.executable_inode))
    );
    assert_eq!(
        provenance
            .target_device
            .as_ref()
            .map(|value| (value.major, value.minor)),
        Some((ready.device_major, ready.device_minor))
    );
    assert_eq!(holder.cgroup.as_ref(), ready.cgroup.as_ref());
    let one = 1_u64.to_ne_bytes();
    assert_eq!(
        unsafe { libc::write(eventfd.as_raw_fd(), one.as_ptr().cast(), one.len()) },
        one.len() as isize
    );
    line.clear();
    reader.read_line(&mut line).expect("holder closed message");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap()["kind"],
        "Closed"
    );
    assert!(child.wait().expect("wait holder").success());
}

#[test]
#[ignore = "requires the root-only sacrificial VT runner"]
fn real_vt_explicit_recovery_after_holder_close_resolves_seat() {
    let target = candidate_vt();
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let socket = directory.path().join("ready.sock");
    let listener = UnixListener::bind(&socket).expect("ready listener");
    let eventfd = unsafe { libc::eventfd(0, 0) };
    assert!(eventfd >= 0, "eventfd");
    let eventfd = unsafe { OwnedFd::from_raw_fd(eventfd) };
    let mut child = Command::new(helper())
        .args(["--target-vt", &target.to_string(), "--ready-socket"])
        .arg(&socket)
        .args(["--release-eventfd", &eventfd.as_raw_fd().to_string()])
        .spawn()
        .expect("start VT holder");
    let (stream, _) = listener.accept().expect("holder ready connection");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("holder ready");
    let _: HolderMessage = serde_json::from_str(&line).expect("typed ready");
    assert!(matches!(
        disallocate_virtual_terminal_once(target),
        Err(SupervisorRecoveryError::VtDisallocateBusy)
    ));
    let busy_provenance = inspect_vt_busy(target, &[]);
    assert!(matches!(
        busy_provenance.classification,
        crate::VtBusyClassification::VisibleUserspaceHolder
    ));
    let one = 1_u64.to_ne_bytes();
    assert_eq!(
        unsafe { libc::write(eventfd.as_raw_fd(), one.as_ptr().cast(), one.len()) },
        one.len() as isize
    );
    line.clear();
    reader.read_line(&mut line).expect("holder closed");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap()["kind"],
        "Closed"
    );
    assert!(child.wait().expect("wait holder").success());
    let after = inspect_vt_busy(target, &[]);
    assert!(
        after.visible_holders.is_empty(),
        "holder must be absent before recovery: {after:?}"
    );
    let fixture = tempfile::tempdir().expect("fixture ledger directory");
    let records = fixture.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, fixture.path().join("lock"))
        .expect("fixture ledger");
    ledger
        .create(quarantined_admin_record(
            target,
            after.observed_active_vt.expect("previous active"),
            busy_provenance,
        ))
        .expect("fixture record");
    let host = std::sync::Arc::new(SacrificialRecoveryAdminHost {
        target,
        previous: inspect_vt_busy(target, &[])
            .observed_active_vt
            .expect("previous active"),
        disallocate_calls: AtomicUsize::new(0),
    });
    let (response, published_free, ledger) =
        crate::launcher::supervisor_loop::dispatch_recovery_admin_for_test(
            ledger,
            host.clone(),
            crate::RecoveryAdminRequest::RetryVtDisallocate {
                seat: "seat0".to_owned(),
                record_id: "sacrificial-vt".to_owned(),
                record_sequence: 1,
                acknowledge_indeterminate: None,
            },
        );
    assert!(matches!(
        response,
        crate::RecoveryAdminResponse::RetryAccepted { .. }
    ));
    assert_eq!(host.disallocate_calls.load(Ordering::SeqCst), 1);
    assert!(
        ledger.records.is_empty(),
        "RecordResolved and runtime release remove the record"
    );
    assert!(
        published_free,
        "Free is published only after record removal"
    );
}
