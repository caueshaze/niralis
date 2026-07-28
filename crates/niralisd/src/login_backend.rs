mod local;
mod pam_worker;

use niralis_auth::MockAuthenticator;
use niralis_discovery::ResolvedSessionLaunchSpec;
use niralis_protocol::SessionInfo;
use niralis_session::{
    LoginRequestBinding, RecoveryAdminRequest, RecoveryAdminResponse, StartedSession,
};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::{AuthBackend, Config, SessionLauncherBackend};
use crate::error::{NiralisdError, Result};
use crate::session_launcher::{build_session_launcher, build_worker_session_launcher};

pub use local::{LocalLoginBackend, LocalLoginBackendFactory};
pub use pam_worker::PamWorkerLoginBackend;

pub struct LoginAttempt {
    pub username: String,
    pub password: Zeroizing<String>,
    pub session: SessionInfo,
    pub launch_spec: ResolvedSessionLaunchSpec,
    pub attempt_id: u64,
    pub connection: Option<LoginRequestBinding>,
}

static NEXT_LOGIN_ATTEMPT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_login_attempt_id() -> u64 {
    let id = NEXT_LOGIN_ATTEMPT_ID.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        NEXT_LOGIN_ATTEMPT_ID.fetch_add(1, Ordering::Relaxed)
    } else {
        id
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LoginBackendError {
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("authenticated session failed")]
    AuthenticatedSessionFailed,
    #[error("login infrastructure failed")]
    InfrastructureFailed,
    #[error("session seat is unavailable")]
    SeatUnavailable,
    #[error("session worker died and was recovered")]
    WorkerDiedAndWasRecovered,
    #[error("session worker recovery is incomplete")]
    WorkerRecoveryIncomplete,
}

pub trait LoginBackend: Send + Sync {
    fn login(
        &self,
        attempt: LoginAttempt,
    ) -> std::result::Result<StartedSession, LoginBackendError>;

    fn shutdown_sessions(&self) {}

    fn cancel_login(&self, _binding: &LoginRequestBinding) -> bool {
        false
    }

    fn recovery_admin(
        &self,
        _request: RecoveryAdminRequest,
    ) -> std::result::Result<RecoveryAdminResponse, LoginBackendError> {
        Err(LoginBackendError::InfrastructureFailed)
    }
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

    fn shutdown_sessions(&self) {
        (**self).shutdown_sessions();
    }

    fn cancel_login(&self, binding: &LoginRequestBinding) -> bool {
        (**self).cancel_login(binding)
    }

    fn recovery_admin(
        &self,
        request: RecoveryAdminRequest,
    ) -> std::result::Result<RecoveryAdminResponse, LoginBackendError> {
        (**self).recovery_admin(request)
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
        niralis_session::SessionError::SessionSeatUnavailable => LoginBackendError::SeatUnavailable,
        niralis_session::SessionError::WorkerDiedAndWasRecovered => {
            LoginBackendError::WorkerDiedAndWasRecovered
        }
        niralis_session::SessionError::WorkerRecoveryIncomplete => {
            LoginBackendError::WorkerRecoveryIncomplete
        }
        niralis_session::SessionError::PersistentRecoveryUnavailable => {
            LoginBackendError::InfrastructureFailed
        }
        _ => LoginBackendError::InfrastructureFailed,
    }
}
