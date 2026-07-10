use niralis_session::{SessionExecPlan, SessionRequest, StartedSession, WorkerSessionLauncher};
use std::os::unix::ffi::OsStrExt;

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
                SessionExecPlan {
                    source_path: attempt
                        .launch_spec
                        .source_path
                        .as_os_str()
                        .as_bytes()
                        .to_vec(),
                    executable: attempt
                        .launch_spec
                        .executable
                        .as_os_str()
                        .as_bytes()
                        .to_vec(),
                    argv: attempt
                        .launch_spec
                        .argv
                        .iter()
                        .map(|arg| arg.as_bytes().to_vec())
                        .collect(),
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
