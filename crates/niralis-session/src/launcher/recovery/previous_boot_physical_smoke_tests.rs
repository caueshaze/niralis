use super::previous_boot_physical_smoke_control::{
    clear_control_file, read_optional_control_file, write_control_file,
};
use super::previous_boot_physical_smoke_storage::{ensure_secure_root, seed_record};
use super::*;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

#[test]
fn run_id_rejects_path_control_characters() {
    for value in [
        "",
        "../escape",
        "Upper",
        "with space",
        "-leading",
        "trailing-",
    ] {
        assert!(PhysicalPreviousBootSmokePaths::for_run_id(value).is_err());
    }
}

#[test]
fn seed_has_only_non_replayable_historical_operations() {
    let directory = tempdir().unwrap();
    let paths =
        PhysicalPreviousBootSmokePaths::under_root(directory.path().to_path_buf(), "run").unwrap();
    let value = seed_record(&paths, "00000000-0000-4000-8000-000000000001".to_owned());
    assert_eq!(historical_not_replayed(&value).len(), 4);
    assert!(validate_historical_record(&value).is_empty());
}

#[test]
fn previous_boot_preflight_rejects_same_boot_before_launcher() {
    let directory = tempdir().unwrap();
    let paths =
        PhysicalPreviousBootSmokePaths::under_root(directory.path().to_path_buf(), "run").unwrap();
    let smoke = PhysicalPreviousBootSmoke::new(paths.clone());
    ensure_secure_root(paths.root()).unwrap();
    let mut ledger =
        PersistentRecoveryLedger::open(paths.recovery_dir(), paths.recovery_lock()).unwrap();
    ledger
        .create(seed_record(
            &paths,
            "00000000-0000-4000-8000-000000000001".to_owned(),
        ))
        .unwrap();
    drop(ledger);
    assert!(smoke
        .assert_previous_boot_ready_against("00000000-0000-4000-8000-000000000001")
        .is_err());
}

#[test]
fn physical_failpoint_parser_is_closed() {
    assert!(PhysicalPreviousBootSmokeFailpoint::parse("after_historical_resolved").is_ok());
    assert!(PhysicalPreviousBootSmokeFailpoint::parse("before_unlink").is_err());
}

#[test]
fn fresh_smoke_root_becomes_private_before_ledger_open() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run");
    ensure_secure_root(&path).unwrap();
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn root_owned_control_file_is_authoritative_when_environment_is_absent() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("failpoint.env");
    write_control_file(&path, "after_historical_resolved").unwrap();
    assert_eq!(
        read_optional_control_file(&path).unwrap(),
        Some(PhysicalPreviousBootSmokeFailpoint::AfterHistoricalResolved)
    );
    clear_control_file(&path).unwrap();
    assert_eq!(read_optional_control_file(&path).unwrap(), None);
}
