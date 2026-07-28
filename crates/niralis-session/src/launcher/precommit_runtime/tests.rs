use super::*;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn reserved_record_round_trips_and_removes_exact_file() {
    let root = tempdir().unwrap();
    let mut store =
        PreCommitRuntimeStore::open(root.path().join("records"), root.path().join("lock")).unwrap();
    let binding = store.create_reserved("tx-1", 1, "seat0", 1).unwrap();
    let binding = store
        .update_stage(
            binding,
            "worker_attached",
            Some("tx-1"),
            Some(std::process::id()),
        )
        .unwrap();
    store.remove(&binding).unwrap();
    assert!(store.records.is_empty());
}

#[test]
fn startup_removes_previous_boot_without_signaling_current_process() {
    let root = tempdir().unwrap();
    let mut store =
        PreCommitRuntimeStore::open(root.path().join("records"), root.path().join("lock")).unwrap();
    let mut binding = store.create_reserved("tx-1", 1, "seat0", 1).unwrap();
    binding.record.boot_id = "boot-old".into();
    store.commit(binding.record.clone()).unwrap();
    let summary = store.reconcile_startup(None);
    assert_eq!(summary.cleared, 1);
    assert!(store.records.is_empty());
}

#[test]
fn startup_quarantines_indeterminate_worker_identity() {
    let root = tempdir().unwrap();
    let mut store =
        PreCommitRuntimeStore::open(root.path().join("records"), root.path().join("lock")).unwrap();
    let binding = store.create_reserved("tx-1", 1, "seat0", 1).unwrap();
    let binding = store
        .update_stage(
            binding,
            "worker_attached",
            Some("tx-1"),
            Some(std::process::id()),
        )
        .unwrap();
    let mut mutated = binding.record.clone();
    mutated.worker_starttime = Some(1);
    store.commit(mutated).unwrap();
    let summary = store.reconcile_startup(None);
    assert_eq!(summary.quarantined, 1);
    assert!(store.seat_startup_quarantined("seat0"));
}

#[test]
fn startup_reconciles_exact_orphan_worker() {
    let root = tempdir().unwrap();
    let mut store =
        PreCommitRuntimeStore::open(root.path().join("records"), root.path().join("lock")).unwrap();
    let mut child = Command::new("sleep").arg("5").spawn().unwrap();
    let binding = store.create_reserved("tx-1", 1, "seat0", 1).unwrap();
    let _binding = store
        .update_stage(binding, "worker_attached", Some("tx-1"), Some(child.id()))
        .unwrap();
    let summary = store.reconcile_startup(None);
    let _ = child.wait();
    assert_eq!(summary.cleared, 1);
    assert!(store.records.is_empty());
}
