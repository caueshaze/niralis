use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use niralis_auth::{
    AuthError, AuthSessionError, AuthenticatedTransaction, AuthenticatedUser, Authenticator,
};
use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{SessionRequest, WorkerEnvelope, WorkerRequest, WorkerSecret};

use crate::identity::{
    GroupResolutionError, IdentityError, SupplementaryGroupsResolver, UnixIdentity,
    UnixIdentityResolver,
};
use crate::runtime::WorkerAuthenticatorFactory;

#[derive(Clone, Default)]
pub(super) struct TrackingState {
    pub(super) authenticate_calls: Arc<AtomicUsize>,
    pub(super) resolve_calls: Arc<AtomicUsize>,
    pub(super) groups_calls: Arc<AtomicUsize>,
    pub(super) open_calls: Arc<AtomicUsize>,
    pub(super) drops: Arc<AtomicUsize>,
}

pub(super) struct StubFactory {
    pub(super) state: TrackingState,
    pub(super) auth_result: Result<(), AuthError>,
    pub(super) open_ok: bool,
    pub(super) open_panics: bool,
    pub(super) pam_username: &'static str,
}

impl WorkerAuthenticatorFactory for StubFactory {
    fn build(&self, _pam_service: &str) -> Box<dyn Authenticator> {
        Box::new(StubAuthenticator {
            state: self.state.clone(),
            auth_result: self.auth_result.clone(),
            open_ok: self.open_ok,
            open_panics: self.open_panics,
            pam_username: self.pam_username,
        })
    }
}

struct StubAuthenticator {
    state: TrackingState,
    auth_result: Result<(), AuthError>,
    open_ok: bool,
    open_panics: bool,
    pam_username: &'static str,
}

impl Authenticator for StubAuthenticator {
    fn authenticate(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError> {
        self.state.authenticate_calls.fetch_add(1, Ordering::SeqCst);
        match &self.auth_result {
            Ok(()) => Ok(Box::new(StubTransaction {
                user: AuthenticatedUser {
                    username: self.pam_username.to_owned(),
                    display_name: username.to_owned(),
                },
                state: self.state.clone(),
                open_ok: self.open_ok,
                open_panics: self.open_panics,
            })),
            Err(error) => Err(error.clone()),
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

pub(super) struct StubIdentityResolver {
    pub(super) state: TrackingState,
    pub(super) result: Result<UnixIdentity, IdentityError>,
    pub(super) last_username: Arc<Mutex<Option<String>>>,
}

pub(super) struct StubGroupsResolver {
    pub(super) state: TrackingState,
    pub(super) result: Result<Vec<u32>, GroupResolutionError>,
    pub(super) last_username: Arc<Mutex<Option<String>>>,
}

impl SupplementaryGroupsResolver for StubGroupsResolver {
    fn resolve(&self, identity: &UnixIdentity) -> Result<Vec<u32>, GroupResolutionError> {
        self.state.groups_calls.fetch_add(1, Ordering::SeqCst);
        *self
            .last_username
            .lock()
            .expect("last_username mutex should lock") = Some(identity.username.clone());
        self.result.clone()
    }
}

impl UnixIdentityResolver for StubIdentityResolver {
    fn resolve(&self, username: &str) -> Result<UnixIdentity, IdentityError> {
        self.state.resolve_calls.fetch_add(1, Ordering::SeqCst);
        *self
            .last_username
            .lock()
            .expect("last_username mutex should lock") = Some(username.to_owned());
        self.result.clone()
    }
}

pub(super) fn request() -> WorkerEnvelope<WorkerRequest> {
    WorkerEnvelope {
        version: niralis_session::WORKER_PROTOCOL_VERSION,
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

pub(super) fn identity() -> UnixIdentity {
    UnixIdentity {
        username: "caue".to_owned(),
        uid: 1000,
        gid: 1000,
        home: "/home/caue".into(),
        shell: "/bin/bash".into(),
    }
}
