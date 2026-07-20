use super::*;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

fn record(id: &str) -> PersistentRecoveryRecord {
    PersistentRecoveryRecord {
        format_version: RECOVERY_FORMAT_VERSION,
        lifecycle_id: id.to_owned(),
        sequence: 1,
        created_at_unix: 1,
        created_boot_id: "boot-a".to_owned(),
        last_updated_boot_id: "boot-a".to_owned(),
        state: "payload_prepared".to_owned(),
        uid: 1000,
        gid: 1000,
        username: "user".to_owned(),
        session_name: "niri".to_owned(),
        seat: "seat0".to_owned(),
        worker_pid: 1,
        launcher_pid: 1,
        worker_starttime: None,
        worker_executable: None,
        worker_cgroup: None,
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
        operation_ledger: DurableOperationLedger::default(),
        quarantine_reason: None,
    }
}

#[test]
fn durable_transition_reloads_with_monotonic_sequence() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let lock = dir.path().join("lock");
    {
        let mut ledger = PersistentRecoveryLedger::open(&records, &lock).unwrap();
        ledger.create(record("lifecycle-a")).unwrap();
        ledger.transition("lifecycle-a", "started").unwrap();
    }
    let ledger = PersistentRecoveryLedger::open(&records, &lock).unwrap();
    let item = ledger.records().next().unwrap();
    assert_eq!(item.sequence, 2);
    assert_eq!(item.state, "started");
}

#[test]
fn worker_vt_cleanup_journal_transitions_preserve_started_state_and_operation_result() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    ledger.create(record("lifecycle-terminal-vt")).unwrap();

    ledger
        .worker_vt_cleanup_intent("lifecycle-terminal-vt", 2)
        .unwrap();
    let item = ledger.records().next().unwrap();
    assert_eq!(item.state, "started");
    assert_eq!(item.sequence, 2);
    assert_eq!(
        item.operation_ledger.vt_disallocate,
        DurableOperationState::IntentPersisted { attempt_id: 2 }
    );

    ledger
        .worker_vt_cleanup_result(
            "lifecycle-terminal-vt",
            2,
            crate::TerminalVtCleanupResult::Released,
        )
        .unwrap();
    let item = ledger.records().next().unwrap();
    assert_eq!(item.state, "started");
    assert_eq!(item.sequence, 3);
    assert_eq!(
        item.operation_ledger.vt_disallocate,
        DurableOperationState::Confirmed { attempt_id: 2 }
    );
}

#[test]
fn durable_quarantine_records_reason_and_monotonic_sequence() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let lock = dir.path().join("lock");
    {
        let mut ledger = PersistentRecoveryLedger::open(&records, &lock).unwrap();
        ledger.create(record("lifecycle-quarantine")).unwrap();
        ledger
            .quarantine(
                "lifecycle-quarantine",
                StartupRecoveryFailure::PersistentRecordConflict,
            )
            .unwrap();
    }
    let ledger = PersistentRecoveryLedger::open(&records, &lock).unwrap();
    let item = ledger.records().next().unwrap();
    assert_eq!(item.sequence, 2);
    assert_eq!(item.state, "quarantined");
    assert_eq!(
        item.quarantine_reason.as_deref(),
        Some("persistent_record_conflict")
    );
    assert_eq!(
        SupervisorRecoveryError::from_persistent_quarantine(
            item.quarantine_reason.as_deref(),
            &item.state,
        ),
        SupervisorRecoveryError::PersistentRecordConflict,
    );
}

#[test]
fn resolved_record_is_durable_before_unlink() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    ledger.create(record("lifecycle-b")).unwrap();
    ledger.resolve_and_remove("lifecycle-b").unwrap();
    assert_eq!(ledger.records().count(), 0);
    assert!(!records.join("lifecycle-b.json").exists());
}

#[test]
fn unknown_format_is_rejected_without_deletion() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    fs::create_dir_all(&records).unwrap();
    let path = records.join("bad.json");
    fs::write(&path, br#"{\"format_version\":99}"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    assert!(ledger.startup_quarantined());
    assert!(path.exists());
}

#[cfg(any(test, feature = "supervisor-test-fixtures"))]
#[test]
fn previous_boot_reconciliation_resolves_and_removes_record() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    ledger.create(record("lifecycle-previous")).unwrap();
    let provider = SupervisorFixtureRecoveryProvider::successful();
    let summary = StartupRecoveryCoordinator::new(&provider).reconcile(&mut ledger);
    assert_eq!(summary.free, 1);
    assert_eq!(summary.quarantined, 0);
    assert_eq!(ledger.records().count(), 0);
}

#[cfg(any(test, feature = "supervisor-test-fixtures"))]
#[test]
fn startup_conflict_never_selects_a_record_heuristically() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    let mut first = record("lifecycle-one");
    first.created_boot_id = current_boot_id().unwrap();
    first.last_updated_boot_id = first.created_boot_id.clone();
    let mut second = record("lifecycle-two");
    second.created_boot_id = first.created_boot_id.clone();
    second.last_updated_boot_id = second.created_boot_id.clone();
    ledger.create(first).unwrap();
    ledger.create(second).unwrap();
    let provider = SupervisorFixtureRecoveryProvider::successful();
    let summary = StartupRecoveryCoordinator::new(&provider).reconcile(&mut ledger);
    assert_eq!(summary.free, 0);
    assert_eq!(summary.quarantined, 2);
    assert_eq!(ledger.records().count(), 2);
    assert!(ledger.records().all(|record| {
        record.state == "quarantined"
            && record.quarantine_reason.as_deref() == Some("persistent_record_conflict")
    }));
}

#[cfg(any(test, feature = "supervisor-test-fixtures"))]
#[test]
fn previous_boot_duplicate_records_clear_after_non_destructive_validation() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    ledger.create(record("lifecycle-old-one")).unwrap();
    ledger.create(record("lifecycle-old-two")).unwrap();
    let provider = SupervisorFixtureRecoveryProvider::successful();
    let summary = StartupRecoveryCoordinator::new(&provider).reconcile(&mut ledger);
    assert_eq!(summary.free, 2);
    assert_eq!(summary.quarantined, 0);
    assert_eq!(ledger.records().count(), 0);
}

#[test]
fn indeterminate_kill_intent_is_preserved_without_retry() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let mut persisted = record("lifecycle-indeterminate");
    persisted.created_boot_id = current_boot_id().unwrap();
    persisted.last_updated_boot_id = persisted.created_boot_id.clone();
    persisted.operation_ledger.payload_kill =
        DurableOperationState::IntentPersisted { attempt_id: 7 };
    let mut ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    ledger.create(persisted).unwrap();
    let provider = SupervisorFixtureRecoveryProvider::successful();
    let summary = StartupRecoveryCoordinator::new(&provider).reconcile(&mut ledger);
    assert_eq!(summary.free, 0);
    assert_eq!(summary.quarantined, 1);
    assert_eq!(ledger.records().count(), 1);
}

#[cfg(any(test, feature = "supervisor-test-fixtures"))]
#[test]
fn unknown_scope_inventory_quarantines_without_recovery() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    let mut provider = SupervisorFixtureRecoveryProvider::successful();
    provider.mode = SupervisorFixtureBoundaryMode::UnknownScope;
    ledger.create(record("lifecycle-unknown-scope")).unwrap();
    let summary = StartupRecoveryCoordinator::new(&provider).reconcile(&mut ledger);
    assert_eq!(summary.free, 0);
    assert_eq!(summary.quarantined, 1);
    assert!(ledger.startup_quarantined());
    assert_eq!(
        provider
            .counters
            .emergency_kills
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}
