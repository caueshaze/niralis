use super::*;
use tempfile::tempdir;

#[test]
fn persisted_recovery_intent_consumes_snapshot_and_rebinds_permit() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let mut ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    let mut base = transition_record();
    ledger.create(base.clone()).unwrap();
    let boot = BootIdentity::parse("boot-a").unwrap();
    let initial = RecoveryStateSnapshot::from_record(&boot, base).unwrap();
    let (next, permit) = ledger
        .persist_recovery_intent_from_snapshot::<PayloadKillOperation>(initial, "payload_kill", 2)
        .unwrap();
    assert_eq!(next.record.sequence, 2);
    assert!(permit.matches(&next.record, next.authority.boot_id(), 2));
    base = ledger.records().next().unwrap().clone();
    let (later, _) = ledger
        .persist_recovery_intent_from_snapshot::<SupervisorUnrefOperation>(
            next,
            "supervisor_unref",
            3,
        )
        .unwrap();
    assert_eq!(later.record.sequence, 3);
    assert_eq!(base.sequence, 2);
}

fn transition_record() -> PersistentRecoveryRecord {
    PersistentRecoveryRecord {
        format_version: RECOVERY_FORMAT_VERSION,
        lifecycle_id: "lifecycle-transition".to_owned(),
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
        launcher_starttime: None,
        launcher_executable: None,
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
        vt_busy_provenance: None,
        vt_recovery_attempts: Vec::new(),
    }
}

#[test]
fn logind_and_vt_permits_are_sequence_bound() {
    let dir = tempdir().unwrap();
    let mut ledger =
        PersistentRecoveryLedger::open(dir.path().join("records"), dir.path().join("lock"))
            .unwrap();
    let record = transition_record();
    ledger.create(record.clone()).unwrap();
    let boot = BootIdentity::parse("boot-a").unwrap();
    let snapshot = RecoveryStateSnapshot::from_record(&boot, record).unwrap();
    let (next, logind) = ledger
        .persist_recovery_intent_from_snapshot::<LogindCleanupOperation>(
            snapshot,
            "logind_termination",
            2,
        )
        .unwrap();
    assert!(logind.matches(&next.record, next.authority.boot_id(), 2));
    let (next, vt) = ledger
        .persist_recovery_intent_from_snapshot::<VtRecoveryOperation>(next, "vt_disallocate", 3)
        .unwrap();
    assert!(vt.matches(&next.record, next.authority.boot_id(), 3));
}

#[test]
fn previous_boot_snapshot_cannot_create_effect_permit() {
    let dir = tempdir().unwrap();
    let mut ledger =
        PersistentRecoveryLedger::open(dir.path().join("records"), dir.path().join("lock"))
            .unwrap();
    let record = transition_record();
    ledger.create(record.clone()).unwrap();
    let boot = BootIdentity::parse("boot-b").unwrap();
    let snapshot = RecoveryStateSnapshot::from_record(&boot, record).unwrap();
    assert!(ledger
        .persist_recovery_intent_from_snapshot::<LogindCleanupOperation>(
            snapshot,
            "logind_termination",
            2
        )
        .is_err());
}

#[test]
fn record_resolved_does_not_remove_record_or_publish_free() {
    let dir = tempdir().unwrap();
    let mut ledger =
        PersistentRecoveryLedger::open(dir.path().join("records"), dir.path().join("lock"))
            .unwrap();
    let record = transition_record();
    let id = record.lifecycle_id.clone();
    ledger.create(record.clone()).unwrap();
    let boot = BootIdentity::parse("boot-a").unwrap();
    let snapshot = RecoveryStateSnapshot::from_record(&boot, record).unwrap();
    let completion = FinalizationCompletionProof::from_snapshot(&snapshot).unwrap();
    let (resolved_snapshot, resolved, _permit) = ledger
        .mark_record_resolved_typed(snapshot, completion)
        .unwrap();
    assert!(ledger.records().any(|record| record.lifecycle_id == id));
    assert_eq!(resolved_snapshot.record.state, "record_resolved");
    assert_eq!(resolved.sequence, resolved_snapshot.record.sequence);
}

#[test]
fn complete_finalization_chain_removes_before_free() {
    let dir = tempdir().unwrap();
    let mut ledger =
        PersistentRecoveryLedger::open(dir.path().join("records"), dir.path().join("lock"))
            .unwrap();
    let record = transition_record();
    let id = record.lifecycle_id.clone();
    ledger.create(record.clone()).unwrap();
    let boot = BootIdentity::parse("boot-a").unwrap();
    let snapshot = RecoveryStateSnapshot::from_record(&boot, record).unwrap();
    let completion = FinalizationCompletionProof::from_snapshot(&snapshot).unwrap();
    let (snapshot, resolved, permit) = ledger
        .mark_record_resolved_typed(snapshot, completion)
        .unwrap();
    let (snapshot, resolved, confirmed, removal) = ledger
        .confirm_runtime_release_typed(snapshot, resolved, permit)
        .unwrap();
    let receipt = ledger
        .remove_record_typed(snapshot, resolved, confirmed, removal)
        .unwrap();
    assert!(!ledger.records().any(|record| record.lifecycle_id == id));
    let free = ledger.issue_seat_free_permit(receipt).unwrap();
    ledger.consume_seat_free_permit(free).unwrap();
}

#[test]
fn finalization_rejects_stale_snapshot_and_previous_boot() {
    let dir = tempdir().unwrap();
    let mut ledger =
        PersistentRecoveryLedger::open(dir.path().join("records"), dir.path().join("lock"))
            .unwrap();
    let record = transition_record();
    ledger.create(record.clone()).unwrap();
    let boot = BootIdentity::parse("boot-a").unwrap();
    let snapshot = RecoveryStateSnapshot::from_record(&boot, record.clone()).unwrap();
    ledger
        .persist_recovery_intent_from_snapshot::<PayloadKillOperation>(snapshot, "payload_kill", 2)
        .unwrap();
    let stale = RecoveryStateSnapshot::from_record(&boot, record).unwrap();
    let completion = FinalizationCompletionProof::from_snapshot(&stale).unwrap();
    assert!(ledger
        .mark_record_resolved_typed(stale, completion)
        .is_err());
    let previous = RecoveryStateSnapshot::from_record(
        &BootIdentity::parse("boot-b").unwrap(),
        ledger.records().next().unwrap().clone(),
    )
    .unwrap();
    assert!(FinalizationCompletionProof::from_snapshot(&previous).is_err());
}

#[test]
fn removal_rejects_replaced_record_file() {
    let dir = tempdir().unwrap();
    let mut ledger =
        PersistentRecoveryLedger::open(dir.path().join("records"), dir.path().join("lock"))
            .unwrap();
    let record = transition_record();
    let id = record.lifecycle_id.clone();
    ledger.create(record.clone()).unwrap();
    let boot = BootIdentity::parse("boot-a").unwrap();
    let snapshot = RecoveryStateSnapshot::from_record(&boot, record).unwrap();
    let completion = FinalizationCompletionProof::from_snapshot(&snapshot).unwrap();
    let (snapshot, resolved, permit) = ledger
        .mark_record_resolved_typed(snapshot, completion)
        .unwrap();
    let (snapshot, resolved, confirmed, removal) = ledger
        .confirm_runtime_release_typed(snapshot, resolved, permit)
        .unwrap();
    let path = dir.path().join("records").join(format!("{id}.json"));
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    assert!(ledger
        .remove_record_typed(snapshot, resolved, confirmed, removal)
        .is_err());
}
