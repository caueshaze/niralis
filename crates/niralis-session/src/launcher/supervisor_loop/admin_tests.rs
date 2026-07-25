use super::*;
use crate::launcher::recovery_admin_host::{
    ControlledRecoveryAdminEvent, ControlledRecoveryAdminHost, RecoveryAdminBoundaryFacts,
};
use tempfile::tempdir;

fn provenance() -> crate::VtBusyProvenance {
    crate::VtBusyProvenance {
        target_vt: 2,
        observed_active_vt: Some(7),
        target_is_foreground: Some(false),
        target_device: None,
        visible_holders: Vec::new(),
        holders_truncated: false,
        inspection_failures: Vec::new(),
        classification: crate::VtBusyClassification::KernelBusyUnattributed,
        captured_at_boottime_ns: 1,
    }
}

fn record() -> PersistentRecoveryRecord {
    let boot = current_boot_id().unwrap();
    PersistentRecoveryRecord {
        format_version: RECOVERY_FORMAT_VERSION,
        lifecycle_id: "admin-fixture".into(),
        sequence: 1,
        created_at_unix: 1,
        created_boot_id: boot.clone(),
        last_updated_boot_id: boot,
        state: "quarantined".into(),
        uid: 1000,
        gid: 1000,
        username: "fixture".into(),
        session_name: "fixture".into(),
        seat: "seat0".into(),
        worker_pid: 999_991,
        launcher_pid: 999_992,
        launcher_starttime: Some(1),
        launcher_executable: Some((1, 1)),
        worker_starttime: Some(1),
        worker_executable: Some((1, 1)),
        worker_cgroup: None,
        leader_pid: None,
        leader_starttime: None,
        leader_executable: None,
        payload_unit: None,
        transient: Some(true),
        invocation_id: Some("00000000000000000000000000000000".into()),
        object_path: None,
        control_group: None,
        slice: None,
        logind_session_id: Some("none".into()),
        logind_object_path: None,
        target_vt: Some(2),
        previous_vt: Some(7),
        pam_status: "fixture".into(),
        operation_ledger: DurableOperationLedger {
            payload_kill: DurableOperationState::Confirmed { attempt_id: 1 },
            supervisor_unref: DurableOperationState::Confirmed { attempt_id: 2 },
            ..Default::default()
        },
        quarantine_reason: Some("vt_disallocate_busy".into()),
        vt_busy_provenance: Some(provenance()),
        vt_recovery_attempts: Vec::new(),
    }
}

fn state(
    host: Arc<ControlledRecoveryAdminHost>,
) -> (SupervisorLoopState, Arc<Mutex<PersistentRecoveryLedger>>) {
    state_with(host, record())
}

fn state_with(
    host: Arc<ControlledRecoveryAdminHost>,
    record: PersistentRecoveryRecord,
) -> (SupervisorLoopState, Arc<Mutex<PersistentRecoveryLedger>>) {
    let dir = tempdir().unwrap();
    let records = dir.keep().join("records");
    let ledger =
        PersistentRecoveryLedger::open(&records, records.parent().unwrap().join("lock")).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));
    ledger.lock().unwrap().create(record).unwrap();
    let provider = Arc::new(SupervisorFixtureRecoveryProvider::successful());
    (
        SupervisorLoopState::new(provider, host, Some(ledger.clone())),
        ledger,
    )
}

fn host(
    disallocate: Result<(), SupervisorRecoveryError>,
    runtime: Result<(), SupervisorRecoveryError>,
) -> Arc<ControlledRecoveryAdminHost> {
    Arc::new(ControlledRecoveryAdminHost {
        boundary: RecoveryAdminBoundaryFacts::Absent,
        vt: SupervisorVtIdentity {
            seat: "seat0".into(),
            number: 2,
            previous: PreviousVtIdentity { number: 7 },
            device_major: 4,
            device_minor: 2,
        },
        before: provenance(),
        after: provenance(),
        disallocate,
        runtime,
        events: Mutex::new(Vec::new()),
    })
}

fn host_with_boundary(boundary: RecoveryAdminBoundaryFacts) -> Arc<ControlledRecoveryAdminHost> {
    let host = host(Ok(()), Ok(()));
    Arc::new(ControlledRecoveryAdminHost {
        boundary,
        vt: host.vt.clone(),
        before: host.before.clone(),
        after: host.after.clone(),
        disallocate: host.disallocate.clone(),
        runtime: host.runtime.clone(),
        events: Mutex::new(Vec::new()),
    })
}

fn host_with_provenance(before: crate::VtBusyProvenance) -> Arc<ControlledRecoveryAdminHost> {
    let host = host(Ok(()), Ok(()));
    Arc::new(ControlledRecoveryAdminHost {
        boundary: RecoveryAdminBoundaryFacts::Absent,
        vt: host.vt.clone(),
        before,
        after: host.after.clone(),
        disallocate: host.disallocate.clone(),
        runtime: host.runtime.clone(),
        events: Mutex::new(Vec::new()),
    })
}

fn request() -> crate::RecoveryAdminRequest {
    crate::RecoveryAdminRequest::RetryVtDisallocate {
        seat: "seat0".into(),
        record_id: "admin-fixture".into(),
        record_sequence: 1,
        acknowledge_indeterminate: None,
    }
}

#[test]
fn controlled_ebusy_updates_real_ledger_without_linux_host_access() {
    let host = host(Err(SupervisorRecoveryError::VtDisallocateBusy), Ok(()));
    let (mut state, ledger) = state(host.clone());
    assert!(matches!(
        state.recovery_admin(request()).unwrap(),
        crate::RecoveryAdminResponse::RetryAccepted { .. }
    ));
    let record = ledger
        .lock()
        .unwrap()
        .records
        .get("admin-fixture")
        .unwrap()
        .clone();
    assert!(matches!(
        record.operation_ledger.vt_disallocate,
        DurableOperationState::NotStarted
    ));
    assert!(
        matches!(record.vt_recovery_attempts.last().unwrap().state, crate::VtRecoveryAttemptState::Failed { errno } if errno == libc::EBUSY)
    );
    assert_eq!(
        host.events(),
        vec![
            ControlledRecoveryAdminEvent::Boundary,
            ControlledRecoveryAdminEvent::PersistedVtIdentity,
            ControlledRecoveryAdminEvent::InspectVt,
            ControlledRecoveryAdminEvent::DisallocateVtOnce,
            ControlledRecoveryAdminEvent::InspectVt
        ]
    );
}

#[test]
fn controlled_success_removes_record_and_publishes_free_last() {
    let host = host(Ok(()), Ok(()));
    let (mut state, ledger) = state(host.clone());
    assert!(matches!(
        state.recovery_admin(request()).unwrap(),
        crate::RecoveryAdminResponse::RetryAccepted { .. }
    ));
    assert!(ledger.lock().unwrap().records.is_empty());
    assert!(matches!(state.seat, SeatLifecycle::Free));
    assert_eq!(
        host.events().last(),
        Some(&ControlledRecoveryAdminEvent::RuntimeRelease)
    );
}

#[test]
fn controlled_runtime_failure_keeps_resolved_record_and_quarantine() {
    let host = host(Ok(()), Err(SupervisorRecoveryError::BusUnavailable));
    let (mut state, ledger) = state(host.clone());
    assert!(matches!(
        state.recovery_admin(request()).unwrap(),
        crate::RecoveryAdminResponse::Rejected { .. }
    ));
    let record = ledger
        .lock()
        .unwrap()
        .records
        .get("admin-fixture")
        .unwrap()
        .clone();
    assert_eq!(record.state, "record_resolved");
    assert!(matches!(
        record.operation_ledger.runtime_release,
        DurableOperationState::Failed { .. }
    ));
    assert!(!matches!(state.seat, SeatLifecycle::Free));
    assert_eq!(
        host.events().last(),
        Some(&ControlledRecoveryAdminEvent::RuntimeRelease)
    );
}

fn assert_boundary_fact_blocks(fact: RecoveryAdminBoundaryFacts) {
    let host = host_with_boundary(fact);
    let (mut state, ledger) = state(host.clone());
    assert!(matches!(
        state.recovery_admin(request()).unwrap(),
        crate::RecoveryAdminResponse::Rejected { .. }
    ));
    assert!(ledger.lock().unwrap().records.contains_key("admin-fixture"));
    assert_eq!(host.events(), vec![ControlledRecoveryAdminEvent::Boundary]);
}

#[test]
fn boundary_populated_blocks_before_ioctl() {
    assert_boundary_fact_blocks(RecoveryAdminBoundaryFacts::Populated);
}
#[test]
fn worker_alive_blocks_before_ioctl() {
    assert_boundary_fact_blocks(RecoveryAdminBoundaryFacts::WorkerAlive);
}
#[test]
fn launcher_alive_blocks_before_ioctl() {
    assert_boundary_fact_blocks(RecoveryAdminBoundaryFacts::LauncherAlive);
}
include!("admin_tests_cases.rs");
