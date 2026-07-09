use std::path::PathBuf;

use niralis_session_worker::{
    ProcessSessionChildRunner, SessionChildError, SessionChildExpectation, SessionChildRunner,
};

fn runner(binary: &str) -> ProcessSessionChildRunner {
    ProcessSessionChildRunner::new(PathBuf::from(binary)).expect("fixture path should be absolute")
}

fn expectation() -> SessionChildExpectation {
    SessionChildExpectation {
        canonical_username: "canonical-user".to_owned(),
        session_id: "niri".to_owned(),
    }
}

#[test]
fn real_session_child_completes_handshake_and_exits() {
    let runner = runner(env!("CARGO_BIN_EXE_niralis-session-child"));

    let report = runner
        .run_child(expectation())
        .expect("child handshake should succeed");

    assert_eq!(report.canonical_username, "canonical-user");
    assert_eq!(report.session_id, "niri");
    assert!(report.child_pid > 0);
}

#[test]
fn child_without_response_times_out_and_is_reaped() {
    let error = runner(env!("CARGO_BIN_EXE_fixture-child-no-response"))
        .run_child(expectation())
        .expect_err("silent child should time out");
    assert_eq!(error, SessionChildError::TimedOut);
}

#[test]
fn child_that_never_reads_still_times_out() {
    let error = runner(env!("CARGO_BIN_EXE_fixture-child-no-read"))
        .run_child(expectation())
        .expect_err("non-reading child should time out");
    assert_eq!(error, SessionChildError::TimedOut);
}

#[test]
fn ready_child_that_hangs_is_killed_by_exit_deadline() {
    let error = runner(env!("CARGO_BIN_EXE_fixture-child-ready-hang"))
        .run_child(expectation())
        .expect_err("ready child that hangs should time out");
    assert_eq!(error, SessionChildError::TimedOut);
}

#[test]
fn nonzero_child_exit_is_reported_after_handshake() {
    let error = runner(env!("CARGO_BIN_EXE_fixture-child-exit1"))
        .run_child(expectation())
        .expect_err("nonzero child should fail");
    assert_eq!(error, SessionChildError::ExitFailed);
}
