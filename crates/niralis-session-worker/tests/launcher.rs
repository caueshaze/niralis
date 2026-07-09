use std::path::PathBuf;
use std::time::Duration;

use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{
    SessionError, SessionLauncher, SessionRequest, StartedSession, WorkerSecret,
    WorkerSessionLauncher,
};

fn request() -> SessionRequest {
    SessionRequest {
        username: "test".to_owned(),
        session: SessionInfo {
            id: "niri".to_owned(),
            name: "Niri".to_owned(),
            kind: SessionKind::Wayland,
        },
    }
}

fn launcher_for(bin: &str) -> WorkerSessionLauncher {
    WorkerSessionLauncher::new(
        PathBuf::from(bin),
        PathBuf::from("/usr/libexec/niralis-session-child"),
        Duration::from_millis(200),
    )
    .expect("launcher should build")
}

#[test]
fn worker_launcher_returns_started_session() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_niralis-session-worker"));

    let started = launcher
        .start_session(request())
        .expect("worker launcher should succeed");

    assert_eq!(
        started,
        StartedSession {
            username: "test".to_owned(),
            session: SessionInfo {
                id: "niri".to_owned(),
                name: "Niri".to_owned(),
                kind: SessionKind::Wayland,
            },
        }
    );
}

#[test]
fn relative_worker_path_is_rejected() {
    let error = WorkerSessionLauncher::new(
        PathBuf::from("relative-worker"),
        PathBuf::from("/usr/libexec/niralis-session-child"),
        Duration::from_millis(200),
    )
    .expect_err("relative path should be rejected");

    assert_eq!(error, SessionError::InvalidWorkerPath);
}

#[test]
fn missing_worker_fails_generically() {
    let launcher = launcher_for("/definitely/missing/niralis-session-worker");
    let error = launcher
        .start_session(request())
        .expect_err("missing worker should fail");
    assert_eq!(error, SessionError::WorkerSpawnFailed);
}

#[test]
fn invalid_json_response_is_rejected() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-invalid-json"));
    let error = launcher
        .start_session(request())
        .expect_err("invalid json should fail");
    assert_eq!(error, SessionError::WorkerProtocolFailed);
}

#[test]
fn invalid_response_version_is_rejected() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-invalid-version-response"));
    let error = launcher
        .start_session(request())
        .expect_err("invalid version should fail");
    assert_eq!(error, SessionError::WorkerProtocolFailed);
}

#[test]
fn mismatched_ready_response_is_rejected() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-mismatched-ready"));
    let error = launcher
        .start_session(request())
        .expect_err("mismatched ready should fail");
    assert_eq!(error, SessionError::WorkerProtocolFailed);
}

#[test]
fn timeout_worker_is_killed() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-timeout"));
    let error = launcher
        .start_session(request())
        .expect_err("timeout worker should fail");
    assert_eq!(error, SessionError::WorkerTimedOut);
}

#[test]
fn ready_then_hang_times_out() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-ready-then-hang"));
    let error = launcher
        .start_session(request())
        .expect_err("ready then hang should time out");
    assert_eq!(error, SessionError::WorkerTimedOut);
}

#[test]
fn authentication_failed_is_reported() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-auth-failed"));
    let error = launcher
        .start_pam_session(
            request(),
            "niralis".to_owned(),
            WorkerSecret::new("secret".to_owned()),
        )
        .expect_err("auth failure should fail");
    assert_eq!(error, SessionError::AuthenticationFailed);
}

#[test]
fn session_failed_is_reported() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-session-failed"));
    let error = launcher
        .start_pam_session(
            request(),
            "niralis".to_owned(),
            WorkerSecret::new("secret".to_owned()),
        )
        .expect_err("session failure should fail");
    assert_eq!(error, SessionError::AuthenticatedSessionFailed);
}

#[test]
fn auth_failure_with_exit_zero_is_protocol_error() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-auth-failed-exit0"));
    let error = launcher
        .start_pam_session(
            request(),
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
