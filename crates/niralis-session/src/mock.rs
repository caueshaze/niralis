use tracing::info;

use crate::{LoginBackendFactory, SessionLauncher, StartedSession, UnauthenticatedLoginRequest};

#[derive(Debug, Default)]
pub struct MockSessionLauncher;

impl SessionLauncher for MockSessionLauncher {
    fn begin_login(
        &self,
        request: UnauthenticatedLoginRequest,
        secret: crate::LoginSecret,
        factory: &dyn LoginBackendFactory,
    ) -> Result<StartedSession, crate::SessionError> {
        request.validate()?;
        let username = factory.create_unbound()?.authenticate(&request, secret)?;
        info!(
            username = %username,
            session = %request.session.id,
            "mock login admitted and started"
        );

        Ok(StartedSession {
            username,
            session: request.session,
        })
    }
}
