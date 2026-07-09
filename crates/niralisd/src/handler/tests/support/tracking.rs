use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use niralis_auth::{AuthError, AuthenticatedTransaction, AuthenticatedUser, Authenticator};
use niralis_session::{SessionError, SessionLauncher, SessionRequest, StartedSession};

#[derive(Debug, Clone, Default)]
pub(crate) struct TrackingAuthState {
    pub(crate) active: Arc<AtomicUsize>,
    pub(crate) drops: Arc<AtomicUsize>,
}

pub(crate) struct TrackingAuthenticator {
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) state: TrackingAuthState,
    pub(crate) succeed: bool,
}

impl TrackingAuthenticator {
    pub(crate) fn succeeds() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            state: TrackingAuthState::default(),
            succeed: true,
        }
    }

    pub(crate) fn fails() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            state: TrackingAuthState::default(),
            succeed: false,
        }
    }
}

impl Authenticator for TrackingAuthenticator {
    fn authenticate(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.succeed {
            Ok(Box::new(TrackingTransaction::new(
                username.to_owned(),
                self.state.clone(),
            )))
        } else {
            Err(AuthError::LoginFailed)
        }
    }
}

struct TrackingTransaction {
    user: AuthenticatedUser,
    state: TrackingAuthState,
}

impl TrackingTransaction {
    fn new(username: String, state: TrackingAuthState) -> Self {
        state.active.fetch_add(1, Ordering::SeqCst);
        Self {
            user: AuthenticatedUser {
                display_name: username.clone(),
                username,
            },
            state,
        }
    }
}

impl AuthenticatedTransaction for TrackingTransaction {
    fn user(&self) -> &AuthenticatedUser {
        &self.user
    }
}

impl Drop for TrackingTransaction {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::SeqCst);
        self.state.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default)]
pub(crate) struct CountingSessionLauncher {
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) last_request: Arc<Mutex<Option<SessionRequest>>>,
}

impl SessionLauncher for CountingSessionLauncher {
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self
            .last_request
            .lock()
            .expect("request mutex should not be poisoned") = Some(request.clone());
        Ok(StartedSession {
            username: request.username,
            session: request.session,
        })
    }
}

#[derive(Debug)]
pub(crate) struct TrackingSessionLauncher {
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) active_during_launch: Arc<AtomicUsize>,
    pub(crate) fail: bool,
    pub(crate) state: TrackingAuthState,
}

impl TrackingSessionLauncher {
    pub(crate) fn succeeds(state: TrackingAuthState) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            active_during_launch: Arc::new(AtomicUsize::new(0)),
            fail: false,
            state,
        }
    }

    pub(crate) fn fails(state: TrackingAuthState) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            active_during_launch: Arc::new(AtomicUsize::new(0)),
            fail: true,
            state,
        }
    }
}

impl SessionLauncher for TrackingSessionLauncher {
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.active_during_launch
            .store(self.state.active.load(Ordering::SeqCst), Ordering::SeqCst);
        if self.fail {
            Err(SessionError::StartFailed)
        } else {
            Ok(StartedSession {
                username: request.username,
                session: request.session,
            })
        }
    }
}
