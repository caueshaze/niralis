use niralis_discovery::{DiscoveryError, SessionDirectory, UserDirectory};
use niralis_protocol::SessionInfo;

use super::niri_session;

#[derive(Debug, Clone)]
pub(crate) struct StubUserDirectory {
    result: StubUserDirectoryResult,
}

impl StubUserDirectory {
    pub(crate) fn with_users(users: Vec<niralis_protocol::UserInfo>) -> Self {
        Self {
            result: StubUserDirectoryResult::Users(users),
        }
    }

    pub(crate) fn with_error() -> Self {
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
pub(crate) struct StubSessionDirectory {
    result: StubSessionDirectoryResult,
}

impl StubSessionDirectory {
    pub(crate) fn with_sessions(sessions: Vec<SessionInfo>) -> Self {
        Self {
            result: StubSessionDirectoryResult::Sessions(sessions),
        }
    }

    pub(crate) fn with_error() -> Self {
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
