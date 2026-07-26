use super::super::*;
use super::finalization_fixture::*;
use std::process::Command;
use tempfile::tempdir;

fn run_child(root: &std::path::Path, failpoint: Option<&str>) -> std::process::ExitStatus {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg("launcher::recovery::previous_boot_finalization::process_tests::fixture_child")
        .arg("--nocapture")
        .env("NIRALIS_PREVIOUS_BOOT_CHILD", "1")
        .env("NIRALIS_PREVIOUS_BOOT_ROOT", root)
        .env("NIRALIS_TEST_BOOT_ID", "boot-current");
    if let Some(stage) = failpoint {
        command.env("NIRALIS_PREVIOUS_BOOT_FAILPOINT", stage);
    } else {
        command.env_remove("NIRALIS_PREVIOUS_BOOT_FAILPOINT");
    }
    command.status().unwrap()
}

#[test]
fn process_restarts_resume_each_previous_boot_failpoint() {
    let stages = [
        PreviousBootFailpoint::BeforeResolutionIntent,
        PreviousBootFailpoint::AfterNotReplayed,
        PreviousBootFailpoint::AfterResolutionIntent,
        PreviousBootFailpoint::AfterHistoricalResolved,
        PreviousBootFailpoint::AfterRuntimeReleaseIntent,
        PreviousBootFailpoint::AfterRuntimeReleaseConfirmed,
        PreviousBootFailpoint::BeforeUnlink,
        PreviousBootFailpoint::AfterUnlinkBeforeReceipt,
        PreviousBootFailpoint::AfterRemovalReceipt,
        PreviousBootFailpoint::BeforeSeatFree,
    ];
    for iteration in 0..20 {
        let root = tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let lock = root.path().join("lock");
        let mut ledger = PersistentRecoveryLedger::open(&recovery, &lock).unwrap();
        ledger.create(record("process-boundary")).unwrap();
        ledger.mark_seat_startup_quarantine("seat0");
        drop(ledger);
        let stage = stages[iteration % stages.len()];
        eprintln!(
            "previous-boot process iteration={iteration} stage={}",
            stage.as_str()
        );
        assert_eq!(
            run_child(root.path(), Some(stage.as_str())).code(),
            Some(86)
        );
        let interrupted = PersistentRecoveryLedger::open(&recovery, &lock).unwrap();
        if let Some(entry) = HistoricalFinalizationJournal::load(&interrupted)
            .unwrap()
            .entry("process-boundary")
        {
            assert_ne!(entry.stage, HistoricalFinalizationStage::FreePublished);
            assert!(interrupted.seat_startup_quarantined("seat0"));
        }
        drop(interrupted);
        assert!(run_child(root.path(), None).success());
        let ledger = PersistentRecoveryLedger::open(&recovery, &lock).unwrap();
        assert_eq!(ledger.records().count(), 0);
        assert!(!ledger.seat_startup_quarantined("seat0"));
        assert_eq!(
            HistoricalFinalizationJournal::load(&ledger)
                .unwrap()
                .entry("process-boundary")
                .unwrap()
                .stage,
            HistoricalFinalizationStage::FreePublished
        );
    }
}

#[test]
fn already_resolved_record_restarts_without_replaying_history() {
    for _ in 0..20 {
        let root = tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let lock = root.path().join("lock");
        let mut ledger = PersistentRecoveryLedger::open(&recovery, &lock).unwrap();
        let mut value = record("resolved-process-boundary");
        value.state = "record_resolved".to_owned();
        ledger.create(value).unwrap();
        drop(ledger);
        assert!(run_child(root.path(), None).success());
        let ledger = PersistentRecoveryLedger::open(&recovery, &lock).unwrap();
        assert_eq!(ledger.records().count(), 0);
        assert_eq!(
            HistoricalFinalizationJournal::load(&ledger)
                .unwrap()
                .entry("resolved-process-boundary")
                .unwrap()
                .stage,
            HistoricalFinalizationStage::FreePublished
        );
    }
}

#[test]
fn fixture_child_is_a_noop_in_the_parent_process() {
    let _ = std::env::var_os("NIRALIS_PREVIOUS_BOOT_CHILD").is_some();
}

#[test]
fn fixture_child() {
    if std::env::var_os("NIRALIS_PREVIOUS_BOOT_CHILD").is_none() {
        return;
    }
    let root = std::path::PathBuf::from(std::env::var_os("NIRALIS_PREVIOUS_BOOT_ROOT").unwrap());
    let recovery = root.join("recovery");
    let lock = root.join("lock");
    let mut ledger = PersistentRecoveryLedger::open(&recovery, &lock).unwrap();
    let record = ledger.records().next().cloned();
    if let Some(record) = record {
        let previous = previous(record.clone());
        let facts = facts();
        let plan = plan_previous_boot_reconciliation(&previous, &facts);
        ledger.mark_seat_startup_quarantine(record.seat);
        let host = host();
        let _ = execute_previous_boot_plan(&mut ledger, &host, &previous, &facts, &plan).unwrap();
        assert!(host
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| matches!(*call, "boot" | "snapshot")));
    } else {
        eprintln!(
            "resume missing record journal={:?}",
            HistoricalFinalizationJournal::load(&ledger)
                .unwrap()
                .entries
        );
        assert_eq!(
            resume_removed_previous_boot_finalization(&mut ledger).unwrap(),
            1
        );
    }
}
