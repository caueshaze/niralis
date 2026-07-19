use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};

use tempfile::TempDir;

struct DaemonFixture {
    child: Child,
    stdin: ChildStdin,
    report: UnixListener,
    barrier: UnixListener,
    worker_report: Option<UnixStream>,
    _directory: TempDir,
    recovery: PathBuf,
    operation_log: PathBuf,
}

impl Drop for DaemonFixture {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGKILL) };
            let _ = self.child.wait();
        }
    }
}

impl DaemonFixture {
    fn spawn(mode: &str) -> Self {
        let directory = tempfile::tempdir().expect("fixture directory");
        let recovery = directory.path().join("recovery");
        let lock = directory.path().join("recovery.lock");
        Self::spawn_with_storage(mode, directory, recovery, lock)
    }

    fn spawn_reusing_storage(mode: &str, recovery: &Path) -> Self {
        let directory = tempfile::tempdir().expect("fixture socket directory");
        let lock = recovery
            .parent()
            .expect("recovery parent")
            .join("recovery.lock");
        Self::spawn_with_storage(mode, directory, recovery.to_path_buf(), lock)
    }

    fn spawn_with_storage(
        mode: &str,
        directory: TempDir,
        recovery: PathBuf,
        lock: PathBuf,
    ) -> Self {
        let report_path = directory.path().join("report.sock");
        let barrier_path = directory.path().join("barrier.sock");
        let report = UnixListener::bind(&report_path).expect("report listener");
        let barrier = UnixListener::bind(&barrier_path).expect("barrier listener");
        let mut child = Command::new(env!("CARGO_BIN_EXE_fixture-supervisor-daemon"))
            .arg(env!("CARGO_BIN_EXE_fixture-supervisor-worker"))
            .arg(&recovery)
            .arg(&lock)
            .arg(mode)
            .arg(&report_path)
            .arg(&barrier_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn fixture daemon");
        let stdin = child.stdin.take().expect("daemon stdin");
        let operation_log = recovery
            .parent()
            .expect("recovery parent")
            .join("operations.log");
        Self {
            child,
            stdin,
            report,
            barrier,
            worker_report: None,
            _directory: directory,
            recovery,
            operation_log,
        }
    }

    fn receive_barrier(&self) -> String {
        let (stream, _) = self.barrier.accept().expect("barrier connection");
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .expect("barrier line");
        line
    }

    fn start(&mut self) {
        writeln!(self.stdin, "start").expect("start command");
        self.stdin.flush().expect("flush start command");
    }

    fn receive_processes(&mut self) -> [u32; 3] {
        let (stream, _) = self.report.accept().expect("process report");
        let mut line = String::new();
        BufReader::new(&stream)
            .read_line(&mut line)
            .expect("process report line");
        let mut values = line
            .split_ascii_whitespace()
            .map(|value| value.parse().expect("process pid"));
        self.worker_report = Some(stream);
        [
            values.next().expect("worker pid"),
            values.next().expect("leader pid"),
            values.next().expect("payload member pid"),
        ]
    }

    fn kill_exact(&mut self) {
        let pid = self.child.id();
        let pidfd = pidfd_open(pid);
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) }, 0);
        wait_pidfd(&pidfd);
        let status = self.child.wait().expect("daemon wait");
        assert!(status.success() || status.signal() == Some(libc::SIGKILL));
    }

    fn events(&self) -> String {
        fs::read_to_string(&self.operation_log).unwrap_or_default()
    }
}

fn record_path(recovery: &Path) -> PathBuf {
    fs::read_dir(recovery)
        .expect("recovery directory")
        .map(|entry| entry.expect("record entry").path())
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .expect("durable record")
}

fn rewrite_record(recovery: &Path, state: &str, payload_intent: bool) -> PathBuf {
    let path = record_path(recovery);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("record bytes")).expect("record JSON");
    value["state"] = serde_json::Value::String(state.to_owned());
    value["sequence"] = serde_json::Value::from(value["sequence"].as_u64().unwrap() + 1);
    if payload_intent {
        value["operation_ledger"]["payload_kill"] = serde_json::json!({
            "IntentPersisted": { "attempt_id": 91 }
        });
    }
    let temporary = recovery.join(".fixture-record.tmp");
    let bytes = serde_json::to_vec(&value).expect("record encoding");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .expect("temporary record");
    file.write_all(&bytes).expect("temporary record write");
    file.sync_all().expect("temporary record sync");
    drop(file);
    fs::rename(&temporary, &path).expect("record replacement");
    let directory = fs::File::open(recovery).expect("recovery directory fd");
    directory.sync_all().expect("recovery directory sync");
    path
}

#[test]
fn daemon_a_reaches_durable_started_before_replacement() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    let ready_a = daemon_a.receive_barrier();
    assert!(ready_a.starts_with("ready "), "{ready_a}");
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    let started = daemon_a.receive_barrier();
    assert!(started.starts_with("started "), "{started}");

    let records = fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .map(|entry| entry.expect("record entry").path())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(&records[0]).expect("durable record bytes"))
            .expect("durable record JSON");
    assert_eq!(record["state"], "started");
    assert!(record["lifecycle_id"].as_str().is_some());
    assert!(record["invocation_id"].as_str().is_some());

    let worker_pid = pidfd_open(processes[0]);
    let leader_pid = pidfd_open(processes[1]);
    let member_pid = pidfd_open(processes[2]);
    assert!(proc_exists(processes[0]));
    assert!(proc_exists(processes[1]));
    assert!(proc_exists(processes[2]));

    let daemon_a_pid = daemon_a.child.id();
    daemon_a.kill_exact();
    assert!(!proc_exists(daemon_a_pid));
    assert!(proc_exists(processes[0]));
    assert!(proc_exists(processes[1]));
    assert!(proc_exists(processes[2]));
    assert!(fs::metadata(&records[0]).is_ok());

    let mut daemon_b =
        DaemonFixture::spawn_reusing_storage("restart-reconciles", &daemon_a.recovery);
    let ready_b = daemon_b.receive_barrier();
    assert!(ready_b.starts_with("ready "), "{ready_b}");
    assert!(daemon_b.child.id() != daemon_a_pid);
    let remaining = fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory after B")
        .map(|entry| {
            let path = entry.expect("remaining record").path();
            (
                path.clone(),
                fs::read_to_string(path).expect("remaining record bytes"),
            )
        })
        .collect::<Vec<_>>();
    assert!(remaining.is_empty(), "remaining records: {remaining:?}");

    kill_pidfd(&worker_pid);
    kill_pidfd(&leader_pid);
    kill_pidfd(&member_pid);
    daemon_b.kill_exact();
}

#[test]
fn same_boot_worker_alive_handoff_completes() {
    let mut daemon_a = DaemonFixture::spawn("worker-alive");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("worker-alive", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    wait_pidfd(&worker);
    assert!(daemon_b.events().contains("worker_sigterm\n"));
    assert!(!daemon_b.events().contains("payload_kill\n"));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn same_boot_worker_gone_payload_is_recovered() {
    let mut daemon_a = DaemonFixture::spawn("payload-recovered");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    kill_pidfd(&worker);
    assert!(proc_exists(processes[1]));
    assert!(proc_exists(processes[2]));

    let mut daemon_b =
        DaemonFixture::spawn_reusing_storage("payload-recovered", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    let events = daemon_b.events();
    let kill = events
        .lines()
        .find(|line| line.starts_with("payload_kill "))
        .unwrap_or_else(|| panic!("invocation-bound payload kill event; events={events:?}"));
    assert!(kill.contains("unit=niralis-payload-"), "event={kill}");
    assert!(kill.contains("invocation="), "event={kill}");
    assert!(
        kill.contains("object_path=/org/freedesktop/systemd1/unit/"),
        "event={kill}"
    );
    assert!(kill.contains("cgroup="), "event={kill}");
    wait_pidfd(&leader);
    assert_eq!(
        daemon_b
            .events()
            .lines()
            .filter(|line| line.starts_with("payload_kill "))
            .count(),
        1
    );
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn same_boot_empty_boundary_skips_emergency_kill() {
    let mut daemon_a = DaemonFixture::spawn("empty");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("empty", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(daemon_b.events().contains("proof:empty_boundary\n"));
    assert!(!daemon_b.events().contains("payload_kill\n"));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    daemon_b.kill_exact();
}

#[test]
fn replacement_quarantines_without_targeting_new_unit() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("replacement", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_some());
    assert!(!daemon_b.events().contains("payload_kill\n"));
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn unknown_scope_never_triggers_destructive_cleanup() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("unknown", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(daemon_b.events().contains("quarantine:unknown_scope\n"));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_some());
    assert!(!daemon_b.events().contains("payload_kill\n"));
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn indeterminate_kill_does_not_repeat() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    kill_pidfd(&worker);
    let record = rewrite_record(&daemon_a.recovery, "started", true);

    let mut daemon_b =
        DaemonFixture::spawn_reusing_storage("payload-recovered", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(daemon_b
        .events()
        .contains("quarantine:indeterminate_payload_kill\n"));
    assert_eq!(
        daemon_b
            .events()
            .lines()
            .filter(|line| line.starts_with("payload_kill "))
            .count(),
        0
    );
    assert!(fs::metadata(record).is_ok());
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn indeterminate_kill_with_empty_boundary_continues() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    rewrite_record(&daemon_a.recovery, "started", true);

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("empty", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert_eq!(
        daemon_b
            .events()
            .lines()
            .filter(|line| line.starts_with("payload_kill "))
            .count(),
        0
    );
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    daemon_b.kill_exact();
}

#[test]
fn vt_ebusy_quarantine_survives_daemon_replacement() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    rewrite_record(&daemon_a.recovery, "vt_disallocate_failed_busy", false);

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("ebusy", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_some());
    assert_eq!(
        daemon_b
            .events()
            .lines()
            .filter(|line| line.starts_with("payload_kill "))
            .count(),
        0
    );
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn second_login_starts_after_reconciled_replacement() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let first = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let first_record = record_path(&daemon_a.recovery);
    let first_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&first_record).expect("first record")).unwrap();
    let first_lifecycle = first_json["lifecycle_id"].as_str().unwrap().to_owned();
    let first_worker = pidfd_open(first[0]);
    let first_leader = pidfd_open(first[1]);
    let first_member = pidfd_open(first[2]);
    daemon_a.kill_exact();

    let mut daemon_b =
        DaemonFixture::spawn_reusing_storage("restart-reconciles", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("resolved recovery directory")
        .next()
        .is_none());
    kill_pidfd(&first_worker);
    kill_pidfd(&first_leader);
    kill_pidfd(&first_member);
    daemon_b.kill_exact();

    let mut daemon_c =
        DaemonFixture::spawn_reusing_storage("restart-reconciles", &daemon_a.recovery);
    assert!(daemon_c.receive_barrier().starts_with("ready "));
    daemon_c.start();
    let second = daemon_c.receive_processes();
    assert!(daemon_c.receive_barrier().starts_with("started "));
    let second_record = record_path(&daemon_a.recovery);
    let second_json: serde_json::Value =
        serde_json::from_slice(&fs::read(second_record).expect("second record")).unwrap();
    assert_ne!(
        first_lifecycle,
        second_json["lifecycle_id"].as_str().unwrap()
    );
    let second_worker = pidfd_open(second[0]);
    let second_leader = pidfd_open(second[1]);
    let second_member = pidfd_open(second[2]);
    daemon_c.kill_exact();
    kill_pidfd(&second_worker);
    kill_pidfd(&second_leader);
    kill_pidfd(&second_member);
}

fn assert_startup_quarantine_mode(mode: &str, expected_event: &str) {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let mut daemon_b = DaemonFixture::spawn_reusing_storage(mode, &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(
        daemon_b.events().contains(expected_event),
        "events={:?}",
        daemon_b.events()
    );
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("quarantined recovery directory")
        .next()
        .is_some());
    assert_eq!(
        daemon_b
            .events()
            .lines()
            .filter(|line| line.starts_with("payload_kill "))
            .count(),
        0
    );
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn systemd_owner_changes_before_kill_quarantine() {
    assert_startup_quarantine_mode("systemd-before-kill", "owner_change:invalidated\n");
}

#[test]
fn systemd_owner_changes_during_kill_quarantine() {
    assert_startup_quarantine_mode("systemd-during-kill", "owner_change:invalidated\n");
}

#[test]
fn systemd_owner_changes_before_proof_quarantine() {
    assert_startup_quarantine_mode("systemd-before-proof", "owner_change:invalidated\n");
}

#[test]
fn logind_owner_changes_before_terminate_quarantine() {
    assert_startup_quarantine_mode("logind-before-terminate", "owner_change:invalidated\n");
}

#[test]
fn logind_owner_changes_during_cleanup_quarantine() {
    assert_startup_quarantine_mode("logind-during-cleanup", "owner_change:invalidated\n");
}

#[test]
fn logind_owner_changes_before_absence_quarantine() {
    assert_startup_quarantine_mode("logind-before-absence", "owner_change:invalidated\n");
}

#[test]
fn unknown_scope_with_known_seat_is_non_destructive() {
    assert_startup_quarantine_mode("unknown-known-seat", "quarantine:unknown_scope\n");
}

#[test]
fn scope_record_conflict_is_non_destructive() {
    assert_startup_quarantine_mode("conflict", "quarantine:scope_record_conflict\n");
}

fn proc_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn pidfd_open(pid: u32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    assert!(fd >= 0, "pidfd_open failed for {pid}");
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

fn kill_pidfd(pidfd: &OwnedFd) {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            0,
            0,
        )
    };
    assert_eq!(result, 0);
    wait_pidfd(pidfd);
}

fn wait_pidfd(pidfd: &OwnedFd) {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut pollfd, 1, 5_000) };
    assert_eq!(result, 1);
    assert_ne!(pollfd.revents & libc::POLLIN, 0);
}
