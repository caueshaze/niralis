mod local;
mod pam_worker;

use niralis_auth::MockAuthenticator;
use niralis_protocol::SessionInfo;
use niralis_session::{StartedSession, WorkerSecret};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::{AuthBackend, Config, SessionLauncherBackend};
use crate::error::{NiralisdError, Result};
use crate::session_launcher::{build_session_launcher, build_worker_session_launcher};

pub use local::LocalLoginBackend;
pub use pam_worker::PamWorkerLoginBackend;

pub struct LoginAttempt {
    pub username: String,
    pub password: Zeroizing<String>,
    pub session: SessionInfo,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LoginBackendError {
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("authenticated session failed")]
    AuthenticatedSessionFailed,
    #[error("login infrastructure failed")]
    InfrastructureFailed,
}

pub trait LoginBackend: Send + Sync {
    fn login(
        &self,
        attempt: LoginAttempt,
    ) -> std::result::Result<StartedSession, LoginBackendError>;

    fn shutdown_sessions(&self) {}
}

impl<T> LoginBackend for Box<T>
where
    T: LoginBackend + ?Sized,
{
    fn login(
        &self,
        attempt: LoginAttempt,
    ) -> std::result::Result<StartedSession, LoginBackendError> {
        (**self).login(attempt)
    }
}

pub fn build_login_backend(config: &Config) -> Result<Box<dyn LoginBackend>> {
    match (config.auth.backend, config.session.launcher) {
        (AuthBackend::Mock, SessionLauncherBackend::Mock)
        | (AuthBackend::Mock, SessionLauncherBackend::Worker) => Ok(Box::new(
            LocalLoginBackend::new(MockAuthenticator, build_session_launcher(config)?),
        )),
        (AuthBackend::Pam, SessionLauncherBackend::Worker) => {
            Ok(Box::new(PamWorkerLoginBackend::new(
                build_worker_session_launcher(config)?,
                config.auth.pam_service.clone(),
            )))
        }
        (AuthBackend::Pam, SessionLauncherBackend::Mock) => {
            Err(NiralisdError::InvalidAuthLauncherCombination)
        }
    }
}

pub(crate) fn map_session_error(error: niralis_session::SessionError) -> LoginBackendError {
    match error {
        niralis_session::SessionError::AuthenticationFailed => {
            LoginBackendError::AuthenticationFailed
        }
        niralis_session::SessionError::AuthenticatedSessionFailed
        | niralis_session::SessionError::StartFailed => {
            LoginBackendError::AuthenticatedSessionFailed
        }
        _ => LoginBackendError::InfrastructureFailed,
    }
}

pub(crate) fn into_worker_secret(password: Zeroizing<String>) -> WorkerSecret {
    let mut password = password;
    WorkerSecret::new(std::mem::take(&mut *password))
}
