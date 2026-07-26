use super::super::*;
use super::finalization_fixture::*;
use tempfile::tempdir;

#[test]
fn clean_plan_finalizes_previous_boot_without_effectful_host_calls() {
    for _ in 0..20 {
        let directory = tempdir().unwrap();
        let mut ledger = PersistentRecoveryLedger::open(
            directory.path().join("records"),
            directory.path().join("lock"),
        )
        .unwrap();
        ledger.create(record("historical")).unwrap();
        ledger.mark_seat_startup_quarantine("seat0".to_owned());
        let previous = match RecoveryRecordEpoch::classify(
            record("historical"),
            BootIdentity::parse("boot-current").unwrap(),
        )
        .unwrap()
        {
            RecoveryRecordEpoch::PreviousBoot(value) => value,
            RecoveryRecordEpoch::SameBoot(_) => panic!("expected previous boot"),
        };
        let facts = facts();
        let plan = plan_previous_boot_reconciliation(&previous, &facts);
        assert!(matches!(
            plan,
            PreviousBootRecoveryPlan::ResolveHistoricalRecord
        ));
        let host = host();
        assert_eq!(
            execute_previous_boot_plan(&mut ledger, &host, &previous, &facts, &plan).unwrap(),
            PreviousBootFinalizationOutcome::SeatFreed
        );
        assert_eq!(ledger.records().count(), 0);
        assert!(!ledger.seat_startup_quarantined("seat0"));
        assert!(host
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| { matches!(*call, "boot" | "snapshot") }));
        let journal = HistoricalFinalizationJournal::load(&ledger).unwrap();
        assert_eq!(
            journal.entry("historical").unwrap().stage,
            HistoricalFinalizationStage::FreePublished
        );
    }
}

#[test]
fn historical_pending_operations_are_recorded_not_replayed() {
    let mut value = record("pending");
    value.operation_ledger.payload_kill = DurableOperationState::IntentPersisted { attempt_id: 4 };
    value.operation_ledger.supervisor_unref = DurableOperationState::Indeterminate {
        attempt_id: 5,
        stage: 1,
    };
    let entries = historical_not_replayed(&value);
    assert_eq!(entries.len(), 2);
    assert!(entries
        .iter()
        .all(|entry| entry.original_state.contains("IntentPersisted")
            || entry.original_state.contains("Indeterminate")));
}

#[test]
fn already_resolved_record_finalizes_without_resolution_transition() {
    let directory = tempdir().unwrap();
    let mut ledger = PersistentRecoveryLedger::open(
        directory.path().join("records"),
        directory.path().join("lock"),
    )
    .unwrap();
    let mut value = record("resolved");
    value.state = "record_resolved".to_owned();
    ledger.create(value.clone()).unwrap();
    let previous =
        match RecoveryRecordEpoch::classify(value, BootIdentity::parse("boot-current").unwrap())
            .unwrap()
        {
            RecoveryRecordEpoch::PreviousBoot(value) => value,
            RecoveryRecordEpoch::SameBoot(_) => panic!("expected previous boot"),
        };
    let facts = facts();
    let plan = plan_previous_boot_reconciliation(&previous, &facts);
    assert!(matches!(
        plan,
        PreviousBootRecoveryPlan::FinalizeAlreadyResolvedRecord
    ));
    let host = host();
    assert_eq!(
        execute_previous_boot_plan(&mut ledger, &host, &previous, &facts, &plan).unwrap(),
        PreviousBootFinalizationOutcome::SeatFreed
    );
    assert!(ledger.records().next().is_none());
}

#[test]
fn changed_plan_cannot_finalize() {
    let directory = tempdir().unwrap();
    let mut ledger = PersistentRecoveryLedger::open(
        directory.path().join("records"),
        directory.path().join("lock"),
    )
    .unwrap();
    ledger.create(record("changed")).unwrap();
    let previous = match RecoveryRecordEpoch::classify(
        record("changed"),
        BootIdentity::parse("boot-current").unwrap(),
    )
    .unwrap()
    {
        RecoveryRecordEpoch::PreviousBoot(value) => value,
        RecoveryRecordEpoch::SameBoot(_) => panic!("expected previous boot"),
    };
    let mut facts = facts();
    let plan = plan_previous_boot_reconciliation(&previous, &facts);
    facts.authority.stable = false;
    let host = host();
    assert!(execute_previous_boot_plan(&mut ledger, &host, &previous, &facts, &plan).is_err());
    assert_eq!(ledger.records().next().unwrap().state, "started");
}

#[test]
fn removal_journal_resumes_without_recreating_record() {
    let directory = tempdir().unwrap();
    let mut ledger = PersistentRecoveryLedger::open(
        directory.path().join("records"),
        directory.path().join("lock"),
    )
    .unwrap();
    let entry = HistoricalFinalizationEntry {
        record_id: "gone".to_owned(),
        lifecycle_id: "gone".to_owned(),
        seat: "seat0".to_owned(),
        boot_id: "boot-current".to_owned(),
        sequence: 8,
        stage: HistoricalFinalizationStage::RemovalIntent,
        not_replayed: Vec::new(),
        device: Some(1),
        inode: Some(2),
        links: Some(1),
    };
    let mut journal = HistoricalFinalizationJournal::default();
    journal.version = 1;
    journal.entries.push(entry);
    journal.persist(&ledger).unwrap();
    assert_eq!(
        resume_removed_previous_boot_finalization(&mut ledger).unwrap(),
        1
    );
    assert!(ledger.records().next().is_none());
    assert_eq!(
        HistoricalFinalizationJournal::load(&ledger)
            .unwrap()
            .entry("gone")
            .unwrap()
            .stage,
        HistoricalFinalizationStage::FreePublished
    );
}
