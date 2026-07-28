use super::*;
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use tempfile::tempdir;

fn process_identity(pid: u32) -> (u64, (u64, u64), String) {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let starttime = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    let executable = fs::metadata(format!("/proc/{pid}/exe")).unwrap();
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .unwrap();
    (starttime, (executable.dev(), executable.ino()), cgroup)
}

fn runtime_release_record(
    pid: u32,
    starttime: u64,
    executable: (u64, u64),
    cgroup: String,
    runtime_release: DurableOperationState,
) -> PersistentRecoveryRecord {
    let boot = current_boot_id().unwrap();
    PersistentRecoveryRecord {
        format_version: RECOVERY_FORMAT_VERSION,
        lifecycle_id: "worker-runtime-release".to_owned(),
        sequence: 3,
        created_at_unix: 0,
        created_boot_id: boot.clone(),
        last_updated_boot_id: boot,
        state: "started".to_owned(),
        uid: 1000,
        gid: 1000,
        username: "fixture-user".to_owned(),
        session_name: "niri".to_owned(),
        seat: "seat0".to_owned(),
        worker_pid: pid,
        launcher_pid: std::process::id(),
        launcher_starttime: Some(starttime),
        launcher_executable: Some(executable),
        worker_starttime: Some(starttime),
        worker_executable: Some(executable),
        worker_cgroup: Some(cgroup),
        leader_pid: None,
        leader_starttime: None,
        leader_executable: None,
        payload_unit: None,
        transient: None,
        invocation_id: None,
        object_path: None,
        control_group: None,
        slice: None,
        logind_session_id: None,
        logind_object_path: None,
        target_vt: None,
        previous_vt: None,
        pam_status: "opened_by_worker".to_owned(),
        operation_ledger: DurableOperationLedger {
            runtime_release,
            ..DurableOperationLedger::default()
        },
        quarantine_reason: None,
        vt_busy_provenance: None,
        vt_recovery_attempts: Vec::new(),
    }
}

fn child_pidfd(record: &PersistentRecoveryRecord, cgroup: &str) -> OwnedFd {
    match rehydrate_process_identity(
        record.worker_pid,
        record.worker_starttime,
        record.worker_executable,
        Some(cgroup),
    ) {
        PersistedProcessIdentity::OriginalStillAlive { pidfd } => pidfd,
        other => panic!("unexpected identity: {other:?}"),
    }
}

fn runtime_release_authority(record: &PersistentRecoveryRecord) -> SameBootRecoveryAuthority {
    SameBootRecoveryAuthority::from_record(
        &BootIdentity::parse(record.created_boot_id.clone()).unwrap(),
        record,
    )
    .unwrap()
}

fn spawn_sleep() -> Child {
    Command::new("/bin/sleep")
        .arg("3600")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn spawn_sigterm_ignoring_sleep() -> Child {
    Command::new("/bin/sh")
        .args(["-c", "trap '' TERM; exec sleep 3600"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
fn validated_runtime_release_confirms_persisted_intent() {
    let root = tempdir().unwrap();
    let records = root.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, root.path().join("lock")).unwrap();
    let mut child = spawn_sleep();
    let pid = child.id();
    let (starttime, executable, cgroup) = process_identity(pid);
    let record = runtime_release_record(
        pid,
        starttime,
        executable,
        cgroup.clone(),
        DurableOperationState::IntentPersisted { attempt_id: 41 },
    );
    let authority = runtime_release_authority(&record);
    ledger.create(record.clone()).unwrap();
    recover_validated_runtime_release(
        &authority,
        &record,
        &mut ledger,
        child_pidfd(&record, &cgroup),
    )
    .unwrap();
    let stored = ledger.records().next().unwrap();
    assert!(matches!(
        stored.operation_ledger.runtime_release,
        DurableOperationState::Confirmed { attempt_id: 41 }
    ));
    let _ = child.wait();
}

#[test]
fn validated_runtime_release_escalates_after_sigterm() {
    let root = tempdir().unwrap();
    let records = root.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, root.path().join("lock")).unwrap();
    let mut child = spawn_sigterm_ignoring_sleep();
    let pid = child.id();
    let (starttime, executable, cgroup) = process_identity(pid);
    let record = runtime_release_record(
        pid,
        starttime,
        executable,
        cgroup.clone(),
        DurableOperationState::NotStarted,
    );
    let authority = runtime_release_authority(&record);
    ledger.create(record.clone()).unwrap();
    recover_validated_runtime_release(
        &authority,
        &record,
        &mut ledger,
        child_pidfd(&record, &cgroup),
    )
    .unwrap();
    let stored = ledger.records().next().unwrap();
    assert!(matches!(
        stored.operation_ledger.runtime_release,
        DurableOperationState::Confirmed { attempt_id: 4 }
    ));
    let _ = child.wait();
}

#[test]
fn validated_runtime_release_quarantines_when_identity_changes_after_indeterminate() {
    let root = tempdir().unwrap();
    let records = root.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, root.path().join("lock")).unwrap();
    let mut child = spawn_sleep();
    let pid = child.id();
    let (starttime, executable, cgroup) = process_identity(pid);
    let record = runtime_release_record(
        pid,
        starttime,
        executable,
        "/tampered".to_owned(),
        DurableOperationState::Indeterminate {
            attempt_id: 52,
            stage: 1,
        },
    );
    let authority = runtime_release_authority(&record);
    ledger.create(record.clone()).unwrap();
    let result = recover_validated_runtime_release(
        &authority,
        &record,
        &mut ledger,
        child_pidfd(&record, &cgroup),
    );
    assert_eq!(
        result,
        Err(StartupRecoveryFailure::WorkerIdentityIndeterminate)
    );
    let _ = child.kill();
    let _ = child.wait();
}
