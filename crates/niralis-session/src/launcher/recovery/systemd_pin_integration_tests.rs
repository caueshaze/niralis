use super::*;
use std::time::{Duration, Instant};

mod systemd_pin_fixture;
use systemd_pin_fixture::SystemdScopeFixture;

#[test]
#[ignore = "requires an explicitly authorized local systemd integration host"]
fn real_invocation_bound_unit_kill_empties_scope() {
    let mut scope = SystemdScopeFixture::start()
        .expect("systemd integration fixture must be created with StartTransientUnit");
    let identity = crate::PayloadScopeIdentity {
        unit_name: scope.unit.clone(),
        invocation_id: scope.invocation.clone(),
        expected_uid: unsafe { libc::geteuid() },
        logind_session_id: crate::LogindSessionId::new("systemd-integration".to_owned())
            .expect("fixture logind id"),
    };
    let leader = SupervisorLeaderPidfd::open(scope.leader_pid).expect("fixture leader pidfd");
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
    let deadline = Instant::now() + Duration::from_secs(2);
    while !matches!(pin.boundary_state(), Ok(SupervisorBoundaryState::Empty)) {
        assert!(
            Instant::now() < deadline,
            "fixture boundary did not become empty"
        );
        std::thread::yield_now();
    }
    assert!(leader.observed_dead().expect("fixture leader observation"));
    assert!(
        std::fs::read_to_string(format!("/sys/fs/cgroup{}/cgroup.procs", pin.control_group))
            .expect("fixture cgroup procs")
            .trim()
            .is_empty()
    );
    assert!(matches!(
        pin.request_emergency_kill(),
        Err(SupervisorRecoveryError::BusDeliveryIndeterminate)
    ));
    pin.release().expect("production Unit.Unref");
    scope
        .wait_for_leader_exit()
        .expect("fixture helper must be reaped after Unit.Kill");
    scope.disarm();
}
