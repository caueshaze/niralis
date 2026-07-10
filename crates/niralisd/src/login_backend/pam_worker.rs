use niralis_session::{SessionRequest, StartedSession, WorkerSessionLauncher};

use super::{into_worker_secret, map_session_error, LoginAttempt, LoginBackend, LoginBackendError};

pub struct PamWorkerLoginBackend {
    launcher: WorkerSessionLauncher,
    pam_service: String,
}

impl PamWorkerLoginBackend {
    pub fn new(launcher: WorkerSessionLauncher, pam_service: String) -> Self {
        Self {
            launcher,
            pam_service,
        }
    }
}

impl LoginBackend for PamWorkerLoginBackend {
    fn login(&self, attempt: LoginAttempt) -> Result<StartedSession, LoginBackendError> {
        self.launcher
            .start_pam_session(
                SessionRequest {
                    username: attempt.username,
                    session: attempt.session,
                },
                self.pam_service.clone(),
                into_worker_secret(attempt.password),
            )
            .map_err(map_session_error)
    }

    fn shutdown_sessions(&self) {
        self.launcher.shutdown_sessions();
    }
}
