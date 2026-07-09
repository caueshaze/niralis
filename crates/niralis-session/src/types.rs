use niralis_protocol::SessionInfo;
use serde::{Deserialize, Serialize};

use crate::SessionError;

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
