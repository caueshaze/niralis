use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use niralis_auth::{
    AuthError, AuthSessionError, AuthenticatedTransaction, AuthenticatedUser, Authenticator,
};
use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{
    SessionRequest, WorkerEnvelope, WorkerRequest, WorkerResponse, WorkerSecret,
    WorkerSessionFailureCode, WORKER_PROTOCOL_VERSION,
};

use crate::runtime::{run_worker_process_with_factory, WorkerAuthenticatorFactory};

#[derive(Clone, Default)]
struct TrackingState {
    authenticate_calls: Arc<AtomicUsize>,
    open_calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

struct StubFactory {
    state: TrackingState,
    authenticate_ok: bool,
    open_ok: bool,
    open_panics: bool,
}

impl WorkerAuthenticatorFactory for StubFactory {
    fn build(&self, _pam_service: &str) -> Box<dyn Authenticator> {
        Box::new(StubAuthenticator {
            state: self.state.clone(),
            authenticate_ok: self.authenticate_ok,
            open_ok: self.open_ok,
            open_panics: self.open_panics,
        })
    }
}

struct StubAuthenticator {
    state: TrackingState,
    authenticate_ok: bool,
    open_ok: bool,
    open_panics: bool,
}

impl Authenticator for StubAuthenticator {
    fn authenticate(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError> {
        self.state.authenticate_calls.fetch_add(1, Ordering::SeqCst);
        if self.authenticate_ok {
            Ok(Box::new(StubTransaction {
                user: AuthenticatedUser {
                    username: username.to_owned(),
                    display_name: username.to_owned(),
                },
                state: self.state.clone(),
                open_ok: self.open_ok,
                open_panics: self.open_panics,
            }))
        } else {
            Err(AuthError::LoginFailed)
        }
    }
}

struct StubTransaction {
    user: AuthenticatedUser,
    state: TrackingState,
    open_ok: bool,
    open_panics: bool,
}

impl AuthenticatedTransaction for StubTransaction {
    fn user(&self) -> &AuthenticatedUser {
        &self.user
    }

    fn open_session(&mut self) -> Result<(), AuthSessionError> {
        self.state.open_calls.fetch_add(1, Ordering::SeqCst);
        if self.open_panics {
            panic!("boom");
        }
        if self.open_ok {
            Ok(())
        } else {
            Err(AuthSessionError::OpenFailed)
        }
    }
}

impl Drop for StubTransaction {
    fn drop(&mut self) {
        self.state.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn request() -> WorkerEnvelope<WorkerRequest> {
    WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message: WorkerRequest::PamSession {
            request: SessionRequest {
                username: "test".to_owned(),
                session: SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: SessionKind::Wayland,
                },
            },
            pam_service: "niralis".to_owned(),
            password: WorkerSecret::new("secret".to_owned()),
        },
    }
}

#[test]
fn pam_worker_returns_ready_after_short_lifecycle() {
    let mut reader = Cursor::new(format!(
        "{}\n",
        serde_json::to_string(&request()).expect("json")
    ));
    let mut writer = Vec::new();
    let state = TrackingState::default();

    run_worker_process_with_factory(
        &mut reader,
        &mut writer,
        &StubFactory {
            state: state.clone(),
            authenticate_ok: true,
            open_ok: true,
            open_panics: false,
        },
    )
    .expect("worker should succeed");

    let response: WorkerEnvelope<WorkerResponse> =
        serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should parse");
    assert_eq!(state.authenticate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.open_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
    assert!(matches!(response.message, WorkerResponse::Ready { .. }));
}

#[test]
fn pam_worker_distinguishes_auth_and_session_failures() {
    for (auth_ok, open_ok, open_panics, expected) in [
        (false, false, false, WorkerResponse::AuthenticationFailed),
        (
            true,
            false,
            false,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::OpenFailed,
            },
        ),
        (
            true,
            false,
            true,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::InternalPanic,
            },
        ),
    ] {
        let mut reader = Cursor::new(format!(
            "{}\n",
            serde_json::to_string(&request()).expect("json")
        ));
        let mut writer = Vec::new();
        let state = TrackingState::default();

        let result = run_worker_process_with_factory(
            &mut reader,
            &mut writer,
            &StubFactory {
                state: state.clone(),
                authenticate_ok: auth_ok,
                open_ok,
                open_panics,
            },
        );

        assert!(result.is_err());
        let response: WorkerEnvelope<WorkerResponse> =
            serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should parse");
        assert_eq!(response.message, expected);
        assert_eq!(state.authenticate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.open_calls.load(Ordering::SeqCst),
            usize::from(auth_ok)
        );
        assert_eq!(state.drops.load(Ordering::SeqCst), usize::from(auth_ok));
    }
}
