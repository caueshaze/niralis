use std::path::PathBuf;

use niralis_session_worker::{
    PrivilegeDropTarget, ProcessSessionChildRunner, SessionChildError, SessionChildExpectation,
    SessionChildRunner,
};

fn runner(binary: &str) -> ProcessSessionChildRunner {
    ProcessSessionChildRunner::new(PathBuf::from(binary)).expect("fixture path should be absolute")
}

fn expectation() -> SessionChildExpectation {
    SessionChildExpectation {
        canonical_username: "canonical-user".to_owned(),
        session_id: "niri".to_owned(),
        target_credentials: PrivilegeDropTarget {
            uid: 1000,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        },
    }
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
