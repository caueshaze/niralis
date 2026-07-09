use std::sync::atomic::Ordering;

use niralis_auth::MockAuthenticator;
use niralis_protocol::NiralisResponse;
use niralis_session::MockSessionLauncher;

use super::support::{
    handler, login_request, niri_session, test_config, CountingAuthenticator,
    CountingSessionLauncher, StubSessionDirectory, StubUserDirectory, TrackingAuthenticator,
    TrackingSessionLauncher,
};
use crate::config::Config;
use crate::handler::login::{login_failed, session_unavailable};
use crate::handler::{DaemonHandler, RequestHandler};
use crate::login_backend::LocalLoginBackend;

#[test]
fn valid_login_returns_canonical_session() {
    assert_eq!(
        handler().handle(login_request("test", "niri")),
        NiralisResponse::LoginOk {
            session: niri_session(),
        }
    );
}

#[test]
fn invalid_password_returns_generic_failure() {
    assert_eq!(
        handler().handle(login_request("wrong-password", "niri")),
        login_failed()
    );
}

#[test]
fn invalid_session_skips_auth_and_launcher() {
    let auth = CountingAuthenticator::always_fails();
    let auth_calls = auth.calls.clone();
    let launcher = CountingSessionLauncher::default();
    let launch_calls = launcher.calls.clone();
    let handler = DaemonHandler::new(
        Config::default(),
        LocalLoginBackend::new(auth, launcher),
        StubUserDirectory::default(),
        StubSessionDirectory::with_sessions(vec![niri_session()]),
    );

    assert_eq!(
        handler.handle(login_request("test", "missing")),
        session_unavailable()
    );
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(launch_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_session_does_not_increment_rate_limit_and_discovery_errors_skip_auth() {
    let auth = CountingAuthenticator::always_fails();
    let auth_calls = auth.calls.clone();
    let handler = DaemonHandler::new(
        test_config(1, 60),
        LocalLoginBackend::new(auth, MockSessionLauncher),
        StubUserDirectory::default(),
        StubSessionDirectory::with_sessions(vec![niri_session()]),
    );

    assert_eq!(
        handler.handle(login_request("test", "missing")),
        session_unavailable()
    );
    assert_eq!(handler.handle(login_request("bad", "niri")), login_failed());
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);

    let auth = CountingAuthenticator::always_fails();
    let auth_calls = auth.calls.clone();
    let launcher = CountingSessionLauncher::default();
    let launch_calls = launcher.calls.clone();
    let handler = DaemonHandler::new(
        Config::default(),
        LocalLoginBackend::new(auth, launcher),
        StubUserDirectory::default(),
        StubSessionDirectory::with_error(),
    );

    assert_eq!(
        handler.handle(login_request("test", "niri")),
        NiralisResponse::Error {
            message: "failed to discover sessions: failed to enumerate users".to_owned(),
        }
    );
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(launch_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn launcher_receives_validated_session_and_rate_limit_still_behaves() {
    let launcher = CountingSessionLauncher::default();
    let seen = launcher.last_request.clone();
    let handler = DaemonHandler::new(
        Config::default(),
        LocalLoginBackend::new(MockAuthenticator, launcher),
        StubUserDirectory::default(),
        StubSessionDirectory::with_sessions(vec![niri_session()]),
    );

    assert!(matches!(
        handler.handle(login_request("test", "niri")),
        NiralisResponse::LoginOk { .. }
    ));
    assert_eq!(
        *seen.lock().expect("request mutex should not be poisoned"),
        Some(niralis_session::SessionRequest {
            username: "test".to_owned(),
            session: niri_session(),
        })
    );

    let auth = CountingAuthenticator::always_fails();
    let calls = auth.calls.clone();
    let handler = DaemonHandler::new(
        test_config(2, 60),
        LocalLoginBackend::new(auth, MockSessionLauncher),
        StubUserDirectory::default(),
        StubSessionDirectory::default(),
    );

    for _ in 0..3 {
        assert_eq!(handler.handle(login_request("bad", "niri")), login_failed());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let auth = CountingAuthenticator::fails_then_succeeds(1);
    let calls = auth.calls.clone();
    let handler = DaemonHandler::new(
        test_config(2, 60),
        LocalLoginBackend::new(auth, MockSessionLauncher),
        StubUserDirectory::default(),
        StubSessionDirectory::default(),
    );

    assert_eq!(handler.handle(login_request("bad", "niri")), login_failed());
    assert!(matches!(
        handler.handle(login_request("test", "niri")),
        NiralisResponse::LoginOk { .. }
    ));
    assert!(matches!(
        handler.handle(login_request("test", "niri")),
        NiralisResponse::LoginOk { .. }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn authenticated_transaction_stays_alive_during_successful_launch() {
    let auth = TrackingAuthenticator::succeeds();
    let state = auth.state.clone();
    let launcher = TrackingSessionLauncher::succeeds(state.clone());
    let launch_calls = launcher.calls.clone();
    let alive_during_launch = launcher.active_during_launch.clone();
    let handler = DaemonHandler::new(
        Config::default(),
        LocalLoginBackend::new(auth, launcher),
        StubUserDirectory::default(),
        StubSessionDirectory::default(),
    );

    assert!(matches!(
        handler.handle(login_request("test", "niri")),
        NiralisResponse::LoginOk { .. }
    ));
    assert_eq!(launch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(alive_during_launch.load(Ordering::SeqCst), 1);
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn authenticated_transaction_is_dropped_after_launcher_error() {
    let auth = TrackingAuthenticator::succeeds();
    let state = auth.state.clone();
    let launcher = TrackingSessionLauncher::fails(state.clone());
    let launch_calls = launcher.calls.clone();
    let alive_during_launch = launcher.active_during_launch.clone();
    let handler = DaemonHandler::new(
        Config::default(),
        LocalLoginBackend::new(auth, launcher),
        StubUserDirectory::default(),
        StubSessionDirectory::default(),
    );

    assert_eq!(
        handler.handle(login_request("test", "niri")),
        NiralisResponse::Error {
            message: "failed to start session".to_owned(),
        }
    );
    assert_eq!(launch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(alive_during_launch.load(Ordering::SeqCst), 1);
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn authentication_failure_does_not_create_transaction() {
    let auth = TrackingAuthenticator::fails();
    let state = auth.state.clone();
    let launcher = TrackingSessionLauncher::succeeds(state.clone());
    let launch_calls = launcher.calls.clone();
    let handler = DaemonHandler::new(
        Config::default(),
        LocalLoginBackend::new(auth, launcher),
        StubUserDirectory::default(),
        StubSessionDirectory::default(),
    );

    assert_eq!(handler.handle(login_request("bad", "niri")), login_failed());
    assert_eq!(launch_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    assert_eq!(state.drops.load(Ordering::SeqCst), 0);
}
