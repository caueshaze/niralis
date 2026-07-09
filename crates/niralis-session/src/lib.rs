use niralis_protocol::SessionInfo;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequest {
    pub username: String,
    pub session: SessionInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedSession {
    pub username: String,
    pub session: SessionInfo,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionError {
    #[error("session start failed")]
    StartFailed,
}

pub trait SessionLauncher: Send + Sync {
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError>;
}

#[derive(Debug, Default)]
pub struct MockSessionLauncher;

impl SessionLauncher for MockSessionLauncher {
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError> {
        info!(
            username = %request.username,
            session = %request.session.id,
            "mock session start requested"
        );

        Ok(StartedSession {
            username: request.username,
            session: request.session,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_launcher_accepts_user_and_session_without_spawning() {
        let launcher = MockSessionLauncher;

        let started = launcher
            .start_session(SessionRequest {
                username: "test".to_owned(),
                session: SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: niralis_protocol::SessionKind::Wayland,
                },
            })
            .expect("mock session launcher should succeed");

        assert_eq!(
            started,
            StartedSession {
                username: "test".to_owned(),
                session: SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: niralis_protocol::SessionKind::Wayland,
                },
            }
        );
    }
}
