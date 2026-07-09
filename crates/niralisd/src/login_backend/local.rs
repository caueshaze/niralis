use niralis_auth::Authenticator;
use niralis_session::{SessionLauncher, SessionRequest, StartedSession};

use super::{map_session_error, LoginAttempt, LoginBackend, LoginBackendError};

pub struct LocalLoginBackend<A, S> {
    authenticator: A,
    session_launcher: S,
}

impl<A, S> LocalLoginBackend<A, S> {
    pub fn new(authenticator: A, session_launcher: S) -> Self {
        Self {
            authenticator,
            session_launcher,
        }
    }
}

impl<A, S> LoginBackend for LocalLoginBackend<A, S>
where
    A: Authenticator,
    S: SessionLauncher,
{
    fn login(&self, attempt: LoginAttempt) -> Result<StartedSession, LoginBackendError> {
        let transaction = self
            .authenticator
            .authenticate(&attempt.username, attempt.password.as_str())
            .map_err(|_| LoginBackendError::AuthenticationFailed)?;
        let request = SessionRequest {
            username: transaction.user().username.clone(),
            session: attempt.session,
        };

        self.session_launcher
            .start_session(request)
            .map_err(map_session_error)
    }
}
