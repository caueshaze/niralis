use std::sync::atomic::Ordering;

use niralis_protocol::NiralisResponse;

use super::support::{
    login_request, test_config, CountingLoginBackend, StubSessionDirectory, StubUserDirectory,
};
use crate::handler::{DaemonHandler, RequestHandler};
use crate::login_backend::LoginBackendError;

#[test]
fn infrastructure_failures_do_not_consume_rate_limit() {
    let backend = CountingLoginBackend::fails(LoginBackendError::InfrastructureFailed);
    let calls = backend.calls.clone();
    let handler = DaemonHandler::new(
        test_config(1, 60),
        backend,
        StubUserDirectory::default(),
        StubSessionDirectory::default(),
    );

    for _ in 0..2 {
        assert_eq!(
            handler.handle(login_request("test", "niri")),
            NiralisResponse::Error {
                message: "failed to start session".to_owned(),
            }
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn authenticated_session_failures_reset_rate_limit() {
    let backend = CountingLoginBackend::fails(LoginBackendError::AuthenticatedSessionFailed);
    let calls = backend.calls.clone();
    let handler = DaemonHandler::new(
        test_config(1, 60),
        backend,
        StubUserDirectory::default(),
        StubSessionDirectory::default(),
    );

    for _ in 0..2 {
        assert_eq!(
            handler.handle(login_request("test", "niri")),
            NiralisResponse::Error {
                message: "failed to start session".to_owned(),
            }
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
