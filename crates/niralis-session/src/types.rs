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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartedSession {
    pub username: String,
    pub session: SessionInfo,
}

pub trait SessionLauncher: Send + Sync {
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError>;
}

impl<T> SessionLauncher for Box<T>
where
    T: SessionLauncher + ?Sized,
{
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError> {
        (**self).start_session(request)
    }
}
