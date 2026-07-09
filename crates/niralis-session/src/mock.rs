use tracing::info;

use crate::{SessionLauncher, SessionRequest, StartedSession};

#[derive(Debug, Default)]
pub struct MockSessionLauncher;

impl SessionLauncher for MockSessionLauncher {
    fn start_session(
        &self,
        request: SessionRequest,
    ) -> Result<StartedSession, crate::SessionError> {
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
