use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use niralis_auth::{AuthError, AuthenticatedUser, Authenticator, MockAuthenticator};
use niralis_discovery::{DiscoveryError, SessionDirectory, UserDirectory};
use niralis_protocol::{NiralisRequest, SessionInfo, SessionKind};
use niralis_session::{
    MockSessionLauncher, SessionError, SessionLauncher, SessionRequest, StartedSession,
};

use crate::config::Config;
use crate::handler::DaemonHandler;

pub(super) fn handler(
) -> DaemonHandler<MockAuthenticator, MockSessionLauncher, StubUserDirectory, StubSessionDirectory>
{
    DaemonHandler::new(
        Config::default(),
        MockAuthenticator,
        MockSessionLauncher,
        StubUserDirectory::with_users(vec![niralis_protocol::UserInfo {
            uid: 1000,
            username: "test".to_owned(),
            display_name: "Test User".to_owned(),
        }]),
        StubSessionDirectory::with_sessions(vec![niri_session()]),
    )
}

pub(super) fn test_config(max_attempts: u32, cooldown_seconds: u64) -> Config {
    let mut config = Config::default();
    config.auth.max_attempts = max_attempts;
    config.auth.cooldown_seconds = cooldown_seconds;
    config
}

pub(super) fn login_request(password: &str, session: &str) -> NiralisRequest {
    NiralisRequest::Login {
        username: "test".to_owned(),
        password: password.to_owned(),
        session: session.to_owned(),
    }
}

pub(super) fn niri_session() -> SessionInfo {
    SessionInfo {
        id: "niri".to_owned(),
        name: "Niri".to_owned(),
        kind: SessionKind::Wayland,
    }
}

pub(super) struct CountingAuthenticator {
    pub(super) calls: Arc<AtomicUsize>,
    failures_before_success: Option<usize>,
}

impl CountingAuthenticator {
    pub(super) fn always_fails() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            failures_before_success: None,
        }
    }

    pub(super) fn fails_then_succeeds(failures_before_success: usize) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            failures_before_success: Some(failures_before_success),
        }
    }
}

impl Authenticator for CountingAuthenticator {
    fn authenticate(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<AuthenticatedUser, AuthError> {
        let previous_calls = self.calls.fetch_add(1, Ordering::SeqCst);
        match self.failures_before_success {
            Some(limit) if previous_calls >= limit => Ok(AuthenticatedUser {
                username: username.to_owned(),
                display_name: username.to_owned(),
            }),
            _ => Err(AuthError::LoginFailed),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct CountingSessionLauncher {
    pub(super) calls: Arc<AtomicUsize>,
    pub(super) last_request: Arc<Mutex<Option<SessionRequest>>>,
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

#[derive(Debug, Clone)]
pub(super) struct StubUserDirectory {
    result: StubUserDirectoryResult,
}

impl StubUserDirectory {
    pub(super) fn with_users(users: Vec<niralis_protocol::UserInfo>) -> Self {
        Self {
            result: StubUserDirectoryResult::Users(users),
        }
    }

    pub(super) fn with_error() -> Self {
        Self {
            result: StubUserDirectoryResult::Error,
        }
    }
}

impl Default for StubUserDirectory {
    fn default() -> Self {
        Self::with_users(Vec::new())
    }
}

impl UserDirectory for StubUserDirectory {
    fn list_users(&self) -> Result<Vec<niralis_protocol::UserInfo>, DiscoveryError> {
        match &self.result {
            StubUserDirectoryResult::Users(users) => Ok(users.clone()),
            StubUserDirectoryResult::Error => Err(DiscoveryError::UserEnumeration),
        }
    }
}

#[derive(Debug, Clone)]
enum StubUserDirectoryResult {
    Users(Vec<niralis_protocol::UserInfo>),
    Error,
}

#[derive(Debug, Clone)]
pub(super) struct StubSessionDirectory {
    result: StubSessionDirectoryResult,
}

impl StubSessionDirectory {
    pub(super) fn with_sessions(sessions: Vec<SessionInfo>) -> Self {
        Self {
            result: StubSessionDirectoryResult::Sessions(sessions),
        }
    }

    pub(super) fn with_error() -> Self {
        Self {
            result: StubSessionDirectoryResult::Error,
        }
    }
}

impl Default for StubSessionDirectory {
    fn default() -> Self {
        Self::with_sessions(vec![niri_session()])
    }
}

impl SessionDirectory for StubSessionDirectory {
    fn list_sessions(&self) -> Result<Vec<SessionInfo>, DiscoveryError> {
        match &self.result {
            StubSessionDirectoryResult::Sessions(sessions) => Ok(sessions.clone()),
            StubSessionDirectoryResult::Error => Err(DiscoveryError::UserEnumeration),
        }
    }

    fn find_session(&self, id: &str) -> Result<Option<SessionInfo>, DiscoveryError> {
        match &self.result {
            StubSessionDirectoryResult::Sessions(sessions) => {
                Ok(sessions.iter().find(|session| session.id == id).cloned())
            }
            StubSessionDirectoryResult::Error => Err(DiscoveryError::UserEnumeration),
        }
    }
}

#[derive(Debug, Clone)]
enum StubSessionDirectoryResult {
    Sessions(Vec<SessionInfo>),
    Error,
}
