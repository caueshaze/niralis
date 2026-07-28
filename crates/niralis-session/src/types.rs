use niralis_protocol::SessionInfo;
use serde::{Deserialize, Serialize};

use crate::SessionError;
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RuntimeSessionId(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogindSessionId(String);

impl LogindSessionId {
    pub fn new(value: String) -> Option<Self> {
        (!value.is_empty() && value.len() <= 128 && !value.as_bytes().contains(&0))
            .then_some(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl RuntimeSessionId {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for RuntimeSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeSessionId([opaque])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    pub username: String,
    pub session: SessionInfo,
}

/// Internal binding issued by niralisd after peer validation. It is metadata
/// only; it never contains credentials and is not reconstructed from a
/// greeter payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequestBinding {
    pub connection_id: String,
    pub connection_epoch: u64,
    pub request_id: u64,
    pub seat: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnauthenticatedLoginRequest {
    pub username: String,
    pub session: SessionInfo,
    pub attempt_id: u64,
    pub launch_plan: Option<crate::SessionExecPlan>,
    pub pam_service: Option<String>,
    pub connection: Option<LoginRequestBinding>,
}

impl UnauthenticatedLoginRequest {
    /// Validates the non-secret portion before any admission, backend, or
    /// worker effect is allowed.  Authentication code must not repair or
    /// normalize these fields after ownership has been acquired.
    pub fn validate(&self) -> Result<(), SessionError> {
        let username = self.username.as_bytes();
        if username.is_empty()
            || username.len() > 256
            || username.contains(&0)
            || self.username.trim() != self.username
            || self.session.id.is_empty()
            || self.session.id.len() > 256
            || self.session.id.as_bytes().contains(&0)
            || self.attempt_id == 0
        {
            return Err(SessionError::WorkerProtocolFailed);
        }
        self.launch_plan
            .as_ref()
            .ok_or(SessionError::WorkerProtocolFailed)?
            .validate()
            .map_err(|_| SessionError::WorkerProtocolFailed)
    }
}

pub type LoginStartOutcome = StartedSession;
pub type LoginStartError = SessionError;

pub trait UnboundLoginBackend: Send {
    fn authenticate(
        self: Box<Self>,
        request: &UnauthenticatedLoginRequest,
        secret: crate::LoginSecret,
    ) -> Result<String, SessionError>;
}

pub trait LoginBackendFactory: Send + Sync {
    fn create_unbound(&self) -> Result<Box<dyn UnboundLoginBackend>, SessionError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartedSession {
    pub username: String,
    pub session: SessionInfo,
}

pub trait SessionLauncher: Send + Sync {
    fn begin_login(
        &self,
        request: UnauthenticatedLoginRequest,
        secret: crate::LoginSecret,
        factory: &dyn LoginBackendFactory,
    ) -> Result<LoginStartOutcome, LoginStartError>;
}

impl<T> SessionLauncher for Box<T>
where
    T: SessionLauncher + ?Sized,
{
    fn begin_login(
        &self,
        request: UnauthenticatedLoginRequest,
        secret: crate::LoginSecret,
        factory: &dyn LoginBackendFactory,
    ) -> Result<LoginStartOutcome, LoginStartError> {
        (**self).begin_login(request, secret, factory)
    }
}
