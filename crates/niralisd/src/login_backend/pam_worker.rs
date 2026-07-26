use niralis_session::{
    LoginBackendFactory, RecoveryAdminRequest, RecoveryAdminResponse, SessionExecPlan,
    SessionLauncher, StartedSession, UnauthenticatedLoginRequest, UnboundLoginBackend,
    WorkerSessionLauncher,
};
use std::os::unix::ffi::OsStrExt;

use super::{map_session_error, LoginAttempt, LoginBackend, LoginBackendError};

pub struct PamWorkerLoginBackend {
    launcher: WorkerSessionLauncher,
    pam_service: String,
}

struct WorkerBackendFactory;
struct UnboundWorkerBackend;

impl LoginBackendFactory for WorkerBackendFactory {
    fn create_unbound(
        &self,
    ) -> Result<Box<dyn UnboundLoginBackend>, niralis_session::SessionError> {
        Ok(Box::new(UnboundWorkerBackend))
    }
}

impl UnboundLoginBackend for UnboundWorkerBackend {
    fn authenticate(
        self: Box<Self>,
        request: &UnauthenticatedLoginRequest,
        _secret: niralis_session::LoginSecret,
    ) -> Result<String, niralis_session::SessionError> {
        Ok(request.username.clone())
    }
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
            .begin_login(
                UnauthenticatedLoginRequest {
                    username: attempt.username,
                    session: attempt.session,
                    attempt_id: attempt.attempt_id,
                    launch_plan: Some(SessionExecPlan {
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
                    }),
                    pam_service: Some(self.pam_service.clone()),
                },
                niralis_session::LoginSecret::new(attempt.password.to_string()),
                &WorkerBackendFactory,
            )
            .map_err(map_session_error)
    }

    fn shutdown_sessions(&self) {
        self.launcher.shutdown_sessions();
    }

    fn recovery_admin(
        &self,
        request: RecoveryAdminRequest,
    ) -> Result<RecoveryAdminResponse, LoginBackendError> {
        self.launcher
            .recovery_admin(request)
            .map_err(map_session_error)
    }
}
