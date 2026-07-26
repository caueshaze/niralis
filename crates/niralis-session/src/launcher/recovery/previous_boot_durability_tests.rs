use super::super::*;
use super::finalization_fixture::record;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

fn open_ledger() -> (tempfile::TempDir, PersistentRecoveryLedger) {
    let root = tempdir().unwrap();
    let ledger =
        PersistentRecoveryLedger::open(root.path().join("records"), root.path().join("lock"))
            .unwrap();
    (root, ledger)
}

fn entry(
    ledger: &PersistentRecoveryLedger,
    stage: HistoricalFinalizationStage,
) -> HistoricalFinalizationEntry {
    let file = ledger.record_file_identity("durable").unwrap();
    HistoricalFinalizationEntry {
        record_id: "durable".to_owned(),
        lifecycle_id: "durable".to_owned(),
        seat: "seat0".to_owned(),
        boot_id: "boot-current".to_owned(),
        sequence: 1,
        stage,
        not_replayed: Vec::new(),
        device: Some(file.device),
        inode: Some(file.inode),
        links: Some(file.links),
    }
}

#[test]
fn journal_ahead_of_ledger_is_typed_and_fail_closed() {
    let (_root, mut ledger) = open_ledger();
    ledger.create(record("durable")).unwrap();
    let mut journal = HistoricalFinalizationJournal::default();
    let mut value = entry(&ledger, HistoricalFinalizationStage::NotReplayed);
    value.sequence = 99;
    journal.entries.push(value);
    assert_eq!(
        journal.validate_against_ledger(&ledger),
        Err(HistoricalDurableStateConflict::JournalAheadOfLedger)
    );
}

#[test]
fn ledger_ahead_of_journal_is_typed_and_fail_closed() {
    let (_root, mut ledger) = open_ledger();
    ledger.create(record("durable")).unwrap();
    ledger.transition("durable", "started_again").unwrap();
    let mut journal = HistoricalFinalizationJournal::default();
    journal
        .entries
        .push(entry(&ledger, HistoricalFinalizationStage::RecordResolved));
    assert_eq!(
        journal.validate_against_ledger(&ledger),
        Err(HistoricalDurableStateConflict::LedgerAheadOfJournal)
    );
}

#[test]
fn removal_receipt_with_record_present_is_rejected() {
    let (_root, mut ledger) = open_ledger();
    ledger.create(record("durable")).unwrap();
    let mut journal = HistoricalFinalizationJournal::default();
    journal
        .entries
        .push(entry(&ledger, HistoricalFinalizationStage::Removed));
    assert_eq!(
        journal.validate_against_ledger(&ledger),
        Err(HistoricalDurableStateConflict::RecordPresentAfterRemovalReceipt)
    );
}

#[test]
fn missing_record_before_removal_is_rejected() {
    let (_root, mut ledger) = open_ledger();
    let mut value = record("durable");
    value.state = "record_resolved".to_owned();
    ledger.create(value).unwrap();
    let file = ledger.record_file_identity("durable").unwrap();
    ledger.remove_record_exact("durable", &file).unwrap();
    let mut journal = HistoricalFinalizationJournal::default();
    journal.entries.push(HistoricalFinalizationEntry {
        record_id: "durable".to_owned(),
        lifecycle_id: "durable".to_owned(),
        seat: "seat0".to_owned(),
        boot_id: "boot-current".to_owned(),
        sequence: 1,
        stage: HistoricalFinalizationStage::RecordResolved,
        not_replayed: Vec::new(),
        device: Some(file.device),
        inode: Some(file.inode),
        links: Some(file.links),
    });
    assert_eq!(
        journal.validate_against_ledger(&ledger),
        Err(HistoricalDurableStateConflict::RecordMissingBeforeRemoval)
    );
}

#[test]
fn replaced_inode_is_rejected_before_resume() {
    let (_root, mut ledger) = open_ledger();
    ledger.create(record("durable")).unwrap();
    let mut journal = HistoricalFinalizationJournal::default();
    let mut value = entry(&ledger, HistoricalFinalizationStage::NotReplayed);
    value.inode = Some(value.inode.unwrap().saturating_add(1));
    journal.entries.push(value);
    assert_eq!(
        journal.validate_against_ledger(&ledger),
        Err(HistoricalDurableStateConflict::ReplacedInode)
    );
}

#[test]
fn abandoned_temporary_file_is_fail_closed() {
    let (root, ledger) = open_ledger();
    std::fs::write(
        root.path().join("records/.previous-boot-finalization.tmp"),
        b"x",
    )
    .unwrap();
    let error = HistoricalFinalizationJournal::load(&ledger).unwrap_err();
    assert!(error.to_string().contains("AbandonedTemporaryFile"));
}

#[test]
fn duplicate_journal_candidate_is_fail_closed() {
    let (root, ledger) = open_ledger();
    std::fs::write(
        root.path().join("records/previous-boot-finalization.old"),
        b"x",
    )
    .unwrap();
    let error = HistoricalFinalizationJournal::load(&ledger).unwrap_err();
    assert!(error.to_string().contains("DuplicateJournalCandidate"));
}

#[test]
fn truncated_journal_is_fail_closed_without_reconstruction() {
    let (root, ledger) = open_ledger();
    std::fs::write(
        ledger.historical_journal_path(),
        br#"{"version":1,"entries":["#,
    )
    .unwrap();
    std::fs::set_permissions(
        ledger.historical_journal_path(),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let error = HistoricalFinalizationJournal::load(&ledger).unwrap_err();
    assert!(error.to_string().contains("CorruptedJournal"));
    assert!(root.path().join("records").exists());
}

#[test]
fn unfinished_journal_restores_seat_quarantine_on_reopen() {
    let (root, mut ledger) = open_ledger();
    ledger.create(record("durable")).unwrap();
    let mut journal = HistoricalFinalizationJournal::default();
    journal.version = 1;
    journal
        .entries
        .push(entry(&ledger, HistoricalFinalizationStage::NotReplayed));
    journal.persist(&ledger).unwrap();
    drop(ledger);
    let reopened =
        PersistentRecoveryLedger::open(root.path().join("records"), root.path().join("lock"))
            .unwrap();
    assert!(reopened.seat_startup_quarantined("seat0"));
}

#[test]
fn sequence_does_not_regress_across_restart() {
    let (root, mut ledger) = open_ledger();
    ledger.create(record("durable")).unwrap();
    ledger.transition("durable", "started_again").unwrap();
    let sequence = ledger.records().next().unwrap().sequence;
    drop(ledger);
    let reopened =
        PersistentRecoveryLedger::open(root.path().join("records"), root.path().join("lock"))
            .unwrap();
    assert_eq!(reopened.records().next().unwrap().sequence, sequence);
}
