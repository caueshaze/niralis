
#[test]
fn auth_failure_with_exit_zero_is_protocol_error() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-auth-failed-exit0"));
    let error = launcher
        .start_pam_session(
            request(),
            plan(),
            "niralis".to_owned(),
            WorkerSecret::new("secret".to_owned()),
        )
        .expect_err("exit zero auth failure should fail");
    assert_eq!(error, SessionError::WorkerProtocolFailed);
}

#[test]
fn oversized_response_is_rejected() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-oversized-response"));
    let error = launcher
        .start_session(request())
        .expect_err("oversized response should fail");
    assert_eq!(error, SessionError::WorkerProtocolFailed);
}

#[test]
fn rejected_response_is_reported() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-rejected"));
    let error = launcher
        .start_session(request())
        .expect_err("rejected response should fail");
    assert_eq!(error, SessionError::WorkerRejected);
}

#[test]
fn no_response_is_rejected() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-no-response"));
    let error = launcher
        .start_session(request())
        .expect_err("empty response should fail");
    assert_eq!(error, SessionError::WorkerProtocolFailed);
}

#[test]
fn ready_with_nonzero_exit_fails() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-ready-exit1"));
    let error = launcher
        .start_session(request())
        .expect_err("nonzero exit should fail");
    assert_eq!(error, SessionError::WorkerProtocolFailed);
}
