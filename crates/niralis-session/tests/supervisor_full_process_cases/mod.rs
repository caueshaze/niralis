mod support;
use support::*;

use std::{io::BufRead, thread};

use niralis_session::{SessionError, SupervisorFixtureBoundaryMode, WorkerSecret};

#[test]
fn worker_sigkill_running_is_recovered_by_supervisor() {
    let fixture = Fixture::new(SupervisorFixtureBoundaryMode::PopulatedThenRecovered, false);
    fixture.launch().expect("fixture session starts");
    let processes = fixture.receive_processes();
    let _cleanup = ProcessCleanup::new(&processes);
    fixture.register_payload(&processes);
    let leader = pidfd_open(processes.leader);
    let member = pidfd_open(processes.member);

    kill_process(processes.worker);
    let snapshot = fixture.wait_recovery();

    assert_recovered(snapshot, 1);
    wait_pidfd_terminal(&leader);
    wait_pidfd_terminal(&member);
}

#[test]
fn worker_dead_with_empty_boundary_skips_emergency_kill() {
    let fixture = Fixture::new(SupervisorFixtureBoundaryMode::AlreadyEmpty, false);
    fixture.launch().expect("fixture session starts");
    let processes = fixture.receive_processes();
    let _cleanup = ProcessCleanup::new(&processes);
    kill_and_observe(processes.leader);
    kill_and_observe(processes.member);

    kill_process(processes.worker);
    let snapshot = fixture.wait_recovery();

    assert_recovered(snapshot, 0);
}

#[test]
fn worker_dies_with_remaining_boundary_member_is_recovered() {
    let fixture = Fixture::new(SupervisorFixtureBoundaryMode::PopulatedThenRecovered, false);
    fixture.launch().expect("fixture session starts");
    let processes = fixture.receive_processes();
    let _cleanup = ProcessCleanup::new(&processes);
    fixture.register_payload(&processes);
    let member = pidfd_open(processes.member);
    kill_and_observe(processes.leader);

    kill_process(processes.worker);
    let snapshot = fixture.wait_recovery();

    assert_recovered(snapshot, 1);
    wait_pidfd_terminal(&member);
}

#[test]
fn replacement_during_supervisor_recovery_quarantines_seat() {
    let fixture = Fixture::new(SupervisorFixtureBoundaryMode::Replacement, false);
    fixture.launch().expect("fixture session starts");
    let processes = fixture.receive_processes();
    let _cleanup = ProcessCleanup::new(&processes);
    fixture.register_payload(&processes);

    kill_process(processes.worker);
    let snapshot = fixture.wait_recovery();

    assert_eq!(snapshot.emergency_kills, 0);
    assert_eq!(snapshot.proofs, 0);
    assert_eq!(snapshot.unrefs, 0);
    assert_eq!(snapshot.logind_terminations, 0);
    assert_eq!(snapshot.vt_recoveries, 0);
    assert_eq!(fixture.launch(), Err(SessionError::SessionSeatUnavailable));
}

#[test]
fn emergency_boundary_timeout_quarantines_without_vt_cleanup() {
    let fixture = Fixture::new(SupervisorFixtureBoundaryMode::Timeout, false);
    fixture.launch().expect("fixture session starts");
    let processes = fixture.receive_processes();
    let _cleanup = ProcessCleanup::new(&processes);
    fixture.register_payload(&processes);

    kill_process(processes.worker);
    let snapshot = fixture.wait_recovery();

    assert_eq!(snapshot.emergency_kills, 0);
    assert_eq!(snapshot.proofs, 0);
    assert_eq!(snapshot.logind_terminations, 0);
    assert_eq!(snapshot.vt_recoveries, 0);
    assert_eq!(fixture.launch(), Err(SessionError::SessionSeatUnavailable));
}

#[test]
fn worker_dies_before_ack_is_recovered_and_client_unblocked() {
    let fixture = Fixture::new(SupervisorFixtureBoundaryMode::PopulatedThenRecovered, false);
    fixture
        .launcher
        .arm_supervisor_fixture_prepare_gate_for_test()
        .expect("arm pre-ack gate");
    let launch = {
        let launcher = fixture.launcher.clone();
        thread::spawn(move || {
            launcher.start_pam_session_for_test(
                session_request(),
                launch_plan(),
                "niralis-supervisor-fixture".to_owned(),
                WorkerSecret::new("fixture-secret".to_owned()),
            )
        })
    };
    let processes = fixture.receive_processes();
    let _cleanup = ProcessCleanup::new(&processes);
    fixture.register_payload(&processes);

    kill_process(processes.worker);
    fixture
        .launcher
        .release_supervisor_fixture_prepare_gate_for_test()
        .expect("release pre-ack gate");
    let snapshot = fixture.wait_recovery();
    let result = launch.join().expect("launch thread");

    assert_eq!(result, Err(SessionError::WorkerDiedAndWasRecovered));
    assert_recovered(snapshot, 1);
}

#[test]
fn worker_dies_after_ack_before_commit_is_recovered() {
    let fixture = Fixture::new(SupervisorFixtureBoundaryMode::PopulatedThenRecovered, true);
    let launch = {
        let launcher = fixture.launcher.clone();
        thread::spawn(move || {
            launcher.start_pam_session_for_test(
                session_request(),
                launch_plan(),
                "niralis-supervisor-fixture".to_owned(),
                WorkerSecret::new("fixture-secret".to_owned()),
            )
        })
    };
    let mut processes = fixture.receive_processes();
    let _cleanup = ProcessCleanup::new(&processes);
    fixture.register_payload(&processes);
    let mut ack = String::new();
    processes
        .report
        .read_line(&mut ack)
        .expect("post-ack report");
    assert_eq!(ack, "ack\n");

    kill_process(processes.worker);
    let snapshot = fixture.wait_recovery();
    let result = launch.join().expect("launch thread");

    assert_eq!(result, Err(SessionError::WorkerDiedAndWasRecovered));
    assert_recovered(snapshot, 1);
}

#[test]
fn recovered_seat_accepts_a_second_login() {
    let fixture = Fixture::new(SupervisorFixtureBoundaryMode::PopulatedThenRecovered, false);
    fixture.launch().expect("first fixture session starts");
    let first = fixture.receive_processes();
    let _first_cleanup = ProcessCleanup::new(&first);
    fixture.register_payload(&first);
    kill_process(first.worker);
    assert_recovered(fixture.wait_recovery(), 1);

    fixture
        .launch()
        .expect("recovered seat accepts second login");
    let second = fixture.receive_processes();
    let _second_cleanup = ProcessCleanup::new(&second);
    fixture.register_payload(&second);
    kill_process(second.worker);
    assert_recovered(fixture.wait_recovery(), 2);
}
