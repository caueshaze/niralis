use super::*;
#[test]
fn v1_record_remains_readable_without_rewrite() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    let mut old = record("v1-record");
    old.format_version = 1;
    let mut ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    ledger.create(old).unwrap();
    drop(ledger);
    let bytes_before = fs::read(records.join("v1-record.json")).unwrap();
    let ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock-2")).unwrap();
    assert_eq!(ledger.records().next().unwrap().format_version, 1);
    assert_eq!(
        fs::read(records.join("v1-record.json")).unwrap(),
        bytes_before
    );
}

#[test]
fn symlink_and_filename_mismatch_are_quarantined_without_deletion() {
    let dir = tempdir().unwrap();
    let records = dir.path().join("records");
    fs::create_dir_all(&records).unwrap();
    let target = dir.path().join("target.json");
    fs::write(&target, br#"{\"format_version\":99}"#).unwrap();
    std::os::unix::fs::symlink(&target, records.join("link.json")).unwrap();
    let mismatch = record("actual-id");
    fs::write(
        records.join("other-id.json"),
        serde_json::to_vec(&mismatch).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        records.join("other-id.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let ledger = PersistentRecoveryLedger::open(&records, dir.path().join("lock")).unwrap();
    assert!(ledger.startup_quarantined());
    assert!(records.join("link.json").exists());
    assert!(records.join("other-id.json").exists());
}

#[test]
fn typed_results_and_record_set_conflicts_fail_closed() {
    let old = record("previous");
    let mut current = record("current");
    current.seat = old.seat.clone();
    current.created_boot_id = "boot-current".into();
    let results = vec![
        DurableRecoveryRecordReadResult::ValidPreviousBoot {
            path: PathBuf::from("previous.json"),
            record: old,
        },
        DurableRecoveryRecordReadResult::ValidSameBoot {
            path: PathBuf::from("current.json"),
            record: current,
        },
    ];
    let classification =
        classify_recovery_record_set(&results, &BootIdentity::parse("boot-current").unwrap());
    assert!(classification.seat_blocked("seat0"));
    assert!(classification
        .conflicts
        .contains(&RecordConflictReason::SameSeatSameBootPrecedence));
}

#[test]
fn unsupported_neighbor_is_global_quarantine() {
    let result = DurableRecoveryRecordReadResult::UnsupportedVersion {
        path: PathBuf::from("future.json"),
        version: 99,
    };
    let classification =
        classify_recovery_record_set(&[result], &BootIdentity::parse("boot-current").unwrap());
    assert!(classification.global_quarantine);
}
