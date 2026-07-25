use super::*;
use std::time::{Duration, Instant};

mod systemd_pin_fixture;
use systemd_pin_fixture::SystemdScopeFixture;

#[test]
#[ignore = "requires an explicitly authorized local systemd integration host"]
fn real_invocation_bound_unit_kill_empties_scope() {
    let recovery_before = recovery_ledger_snapshot();
    let mut scope = SystemdScopeFixture::start(true)
        .expect("systemd integration fixture must be created with StartTransientUnit");
    let identity = crate::PayloadScopeIdentity {
        unit_name: scope.unit.clone(),
        invocation_id: scope.invocation.clone(),
        expected_uid: scope.expected_uid,
        logind_session_id: crate::LogindSessionId::new("systemd-integration".to_owned())
            .expect("fixture logind id"),
    };
    let leader = SupervisorLeaderPidfd::open(scope.leader_pid).expect("fixture leader pidfd");
    let descendant = SupervisorLeaderPidfd::open(
        scope
            .descendant_pid
            .expect("Kill fixture must create a descendant"),
    )
    .expect("fixture descendant pidfd");
    let mut pin = SupervisorPinnedInvocationUnit::acquire(
        identity,
        scope.leader_pid,
        std::process::id(),
        std::process::id(),
        &leader,
    )
    .expect("production invocation-bound Ref and revalidation");
    assert_eq!(pin.object_path, scope.object_path);
    assert_eq!(pin.control_group, scope.control_group);
    pin.request_emergency_kill()
        .expect("production Unit.Kill(all, SIGKILL)");
    // The private helper is the scope leader and its launcher must reap it
    // before cgroup.events can become terminal.
    scope
        .wait_for_launcher_exit()
        .expect("fixture launcher must exit after Unit.Kill");
    let terminal_boundary = wait_for_terminal_boundary(&pin);
    assert!(leader.observed_dead().expect("fixture leader observation"));
    assert!(
        descendant
            .observed_dead()
            .expect("fixture descendant observation"),
        "Unit.Kill(all) left the helper descendant alive"
    );
    if terminal_boundary == SupervisorBoundaryState::Empty {
        assert!(std::fs::read_to_string(format!(
            "/sys/fs/cgroup{}/cgroup.procs",
            pin.control_group
        ))
        .expect("fixture cgroup procs")
        .trim()
        .is_empty());
    }
    assert!(matches!(
        pin.request_emergency_kill(),
        Err(SupervisorRecoveryError::BusDeliveryIndeterminate)
    ));
    pin.release().expect("production Unit.Unref");
    assert_scope_removed(&scope.invocation);
    scope.disarm();
    assert_eq!(recovery_before, recovery_ledger_snapshot());
}

#[test]
#[ignore = "requires an explicitly authorized local systemd integration host"]
fn real_unknown_scope_is_detected_without_kill() {
    let scope = SystemdScopeFixture::start(false)
        .expect("systemd integration fixture must create a sacrificial scope");
    let connection = zbus::blocking::connection::Builder::system()
        .expect("opening system bus")
        .build()
        .expect("connecting system bus");
    let path = resolve_invocation(&connection, &scope.invocation)
        .expect("resolve fixture invocation")
        .expect("fixture scope remains present");
    let before = read_unit_observation(&connection, &path).expect("read fixture before inventory");

    // This is the exact production inventory path.  It must only report the
    // orphan; its first destructive operation is deliberately reserved for
    // the fixture Drop below, after all assertions have completed.
    assert_eq!(
        inventory_unknown_payload_scopes(&[]).expect("production inventory"),
        UnknownScopeInventory::GlobalQuarantine
    );

    let after_path = resolve_invocation(&connection, &scope.invocation)
        .expect("resolve fixture after inventory")
        .expect("inventory must not remove the scope");
    let after =
        read_unit_observation(&connection, &after_path).expect("read fixture after inventory");
    assert_eq!(
        before, after,
        "inventory issued a destructive unit operation"
    );
    assert!(std::path::Path::new(&format!("/proc/{}", scope.leader_pid)).exists());

    // The harness owns the exact invocation identity and performs teardown
    // only after the non-destructive assertions above.
}

#[test]
#[ignore = "requires an explicitly authorized local systemd integration host"]
fn real_known_scope_matches_durable_invocation_identity() {
    let scope = SystemdScopeFixture::start(false)
        .expect("systemd integration fixture must create a sacrificial scope");
    let record = matching_scope_record(&scope);
    let connection = zbus::blocking::connection::Builder::system()
        .expect("opening system bus")
        .build()
        .expect("connecting system bus");
    let canonical_path = resolve_invocation(&connection, &scope.invocation)
        .expect("resolve fixture invocation")
        .expect("fixture scope remains present");
    assert_eq!(record.object_path.as_deref(), Some(canonical_path.as_str()));
    let before =
        read_unit_observation(&connection, &canonical_path).expect("read fixture before inventory");

    assert_eq!(
        inventory_unknown_payload_scopes(&[record]).expect("production inventory"),
        UnknownScopeInventory::None
    );

    let after_path = resolve_invocation(&connection, &scope.invocation)
        .expect("resolve fixture after inventory")
        .expect("inventory must not remove the scope");
    let after =
        read_unit_observation(&connection, &after_path).expect("read fixture after inventory");
    assert_eq!(
        before, after,
        "inventory issued a destructive unit operation"
    );
}

fn matching_scope_record(scope: &SystemdScopeFixture) -> PersistentRecoveryRecord {
    PersistentRecoveryRecord {
        format_version: RECOVERY_FORMAT_VERSION,
        lifecycle_id: "systemd-integration-known-scope".to_owned(),
        sequence: 1,
        created_at_unix: 1,
        created_boot_id: "systemd-integration-boot".to_owned(),
        last_updated_boot_id: "systemd-integration-boot".to_owned(),
        state: "started".to_owned(),
        uid: scope.expected_uid,
        gid: scope.expected_uid,
        username: "systemd-integration".to_owned(),
        session_name: "systemd-integration".to_owned(),
        seat: "seat0".to_owned(),
        worker_pid: 1,
        launcher_pid: 1,
        launcher_starttime: None,
        launcher_executable: None,
        worker_starttime: None,
        worker_executable: None,
        worker_cgroup: None,
        leader_pid: Some(scope.leader_pid),
        leader_starttime: None,
        leader_executable: None,
        payload_unit: Some(scope.unit.clone()),
        transient: Some(true),
        invocation_id: Some(scope.invocation.clone()),
        object_path: Some(scope.object_path.clone()),
        control_group: Some(scope.control_group.clone()),
        slice: Some(format!("user-{}.slice", scope.expected_uid)),
        logind_session_id: Some("systemd-integration".to_owned()),
        logind_object_path: Some("/systemd-integration".to_owned()),
        target_vt: Some(2),
        previous_vt: Some(1),
        pam_status: "opened_by_worker".to_owned(),
        operation_ledger: DurableOperationLedger::default(),
        quarantine_reason: None,
        vt_busy_provenance: None,
        vt_recovery_attempts: Vec::new(),
    }
}

fn wait_for_terminal_boundary(pin: &SupervisorPinnedInvocationUnit) -> SupervisorBoundaryState {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match pin.boundary_state() {
            Ok(state @ (SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent)) => {
                return state;
            }
            _ if Instant::now() < deadline => std::thread::yield_now(),
            state => {
                let cgroup = format!("/sys/fs/cgroup{}", pin.control_group);
                let events = std::fs::read_to_string(format!("{cgroup}/cgroup.events"));
                let procs = std::fs::read_to_string(format!("{cgroup}/cgroup.procs"));
                panic!(
                    "fixture boundary did not become empty: state={state:?}, events={events:?}, procs={procs:?}"
                );
            }
        }
    }
}

fn assert_scope_removed(invocation: &str) {
    let connection = zbus::blocking::connection::Builder::system()
        .expect("opening system bus for fixture cleanup check")
        .build()
        .expect("connecting system bus for fixture cleanup check");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match resolve_invocation(&connection, invocation) {
            Ok(None) => return,
            Ok(Some(_)) if Instant::now() < deadline => std::thread::yield_now(),
            Ok(Some(_)) => panic!("sacrificial scope remained after Unit.Unref"),
            Err(error) => panic!("checking sacrificial scope removal failed: {error:?}"),
        }
    }
}

fn recovery_ledger_snapshot() -> Option<Vec<(String, u64)>> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let mut entries: Vec<_> = std::fs::read_dir("/var/lib/niralis/recovery")
        .expect("reading recovery ledger as root")
        .map(|entry| {
            let entry = entry.expect("reading recovery ledger entry");
            let metadata = entry.metadata().expect("reading recovery ledger metadata");
            (
                entry.file_name().to_string_lossy().into_owned(),
                metadata.len(),
            )
        })
        .collect();
    entries.sort();
    Some(entries)
}
