use niralis_auth::MockAuthenticator;
use niralis_protocol::{NiralisRequest, NiralisResponse, SessionInfo, SessionKind};
use niralis_session::MockSessionLauncher;

use super::support::{handler, StubSessionDirectory, StubUserDirectory};
use crate::config::Config;
use crate::handler::{DaemonHandler, RequestHandler};
use crate::login_backend::LocalLoginBackend;

#[test]
fn handles_status() {
    let response = handler().handle(NiralisRequest::Status);
    match response {
        NiralisResponse::Status { status } => assert_eq!(status.default_session, "niri"),
        other => panic!("expected status response, got {other:?}"),
    }
}

#[test]
fn handles_get_users() {
    assert_eq!(
        handler().handle(NiralisRequest::GetUsers),
        NiralisResponse::Users {
            users: vec![niralis_protocol::UserInfo {
                uid: 1000,
                username: "test".to_owned(),
                display_name: "Test User".to_owned(),
            }]
        }
    );
}

#[test]
fn handles_get_sessions() {
    assert_eq!(
        handler().handle(NiralisRequest::GetSessions),
        NiralisResponse::Sessions {
            sessions: vec![SessionInfo {
                id: "niri".to_owned(),
                name: "Niri".to_owned(),
                kind: SessionKind::Wayland,
            }]
        }
    );
}

#[test]
fn get_sessions_uses_session_directory() {
    let handler = DaemonHandler::new(
        Config::default(),
        LocalLoginBackend::new(MockAuthenticator, MockSessionLauncher),
        StubUserDirectory::default(),
        StubSessionDirectory::with_sessions(vec![SessionInfo {
            id: "plasma".to_owned(),
            name: "Plasma".to_owned(),
            kind: SessionKind::X11,
        }]),
    );

    assert_eq!(
        handler.handle(NiralisRequest::GetSessions),
        NiralisResponse::Sessions {
            sessions: vec![SessionInfo {
                id: "plasma".to_owned(),
                name: "Plasma".to_owned(),
                kind: SessionKind::X11,
            }]
        }
    );
}

#[test]
fn discovery_errors_return_structured_error_response() {
    let handler = DaemonHandler::new(
        Config::default(),
        LocalLoginBackend::new(MockAuthenticator, MockSessionLauncher),
        StubUserDirectory::with_error(),
        StubSessionDirectory::with_error(),
    );

    assert_eq!(
        handler.handle(NiralisRequest::GetUsers),
        NiralisResponse::Error {
            message: "failed to discover users: failed to enumerate users".to_owned(),
        }
    );
    assert_eq!(
        handler.handle(NiralisRequest::GetSessions),
        NiralisResponse::Error {
            message: "failed to discover sessions: failed to enumerate users".to_owned(),
        }
    );
}

#[test]
fn shutdown_and_reboot_are_not_implemented() {
    assert_eq!(
        handler().handle(NiralisRequest::Shutdown),
        NiralisResponse::Error {
            message: "not implemented in phase 1".to_owned(),
        }
    );
    assert_eq!(
        handler().handle(NiralisRequest::Reboot),
        NiralisResponse::Error {
            message: "not implemented in phase 1".to_owned(),
        }
    );
}
