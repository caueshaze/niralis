use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::{
    worker_attempt::WorkerAttempt, SessionError, SessionLauncher, SessionRequest, StartedSession,
    WorkerEnvelope, WorkerRequest, WorkerResponse, WorkerSecret,
};

#[derive(Debug, Clone)]
pub struct WorkerSessionLauncher {
    worker_path: PathBuf,
    session_child_path: PathBuf,
    timeout: Duration,
}

impl WorkerSessionLauncher {
    pub fn new(
        worker_path: PathBuf,
        session_child_path: PathBuf,
        timeout: Duration,
    ) -> Result<Self, SessionError> {
        if !worker_path.is_absolute() || !session_child_path.is_absolute() {
            return Err(SessionError::InvalidWorkerPath);
        }
        Ok(Self {
            worker_path,
            session_child_path,
            timeout,
        })
    }

    pub fn worker_path(&self) -> &Path {
        &self.worker_path
    }

    pub fn start_pam_session(
        &self,
        request: SessionRequest,
        pam_service: String,
        password: WorkerSecret,
    ) -> Result<StartedSession, SessionError> {
        self.start_worker(
            WorkerRequest::PamSession {
                request: request.clone(),
                pam_service,
                password,
                session_child_path: self.session_child_path.clone(),
            },
            expected_started_session(&request),
        )
    }

    fn start_worker(
        &self,
        request: WorkerRequest,
        expected: StartedSession,
    ) -> Result<StartedSession, SessionError> {
        let deadline = Instant::now() + self.timeout;
        let mut attempt = WorkerAttempt::spawn(&self.worker_path, request)?;
        let writer_result = attempt.wait_writer(deadline);
        let response_result = attempt.wait_reader(deadline);
        let status_result = if response_result.is_ok() {
            attempt.wait_child(deadline)
        } else {
            Ok(None)
        };

        let writer_failed = matches!(writer_result, Err(SessionError::WorkerIoFailed));
        let reader_failed = matches!(response_result, Err(SessionError::WorkerIoFailed));
        let status_failed = matches!(status_result, Err(SessionError::WorkerIoFailed));
        if writer_failed || reader_failed || status_failed {
            attempt.kill_and_reap();
        }
        attempt.finish();

        if !writer_failed {
            writer_result?;
        }
        let response = response_result?;
        let status = status_result?.ok_or(SessionError::WorkerProtocolFailed)?;
        debug!(?status, "session worker exited");
        map_response(response, status, expected)
    }
}

impl SessionLauncher for WorkerSessionLauncher {
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError> {
        self.start_worker(
            WorkerRequest::PrepareSession {
                request: request.clone(),
            },
            expected_started_session(&request),
        )
    }
}

fn expected_started_session(request: &SessionRequest) -> StartedSession {
    StartedSession {
        username: request.username.clone(),
        session: request.session.clone(),
    }
}

fn map_response(
    response: WorkerEnvelope<WorkerResponse>,
    status: ExitStatus,
    expected: StartedSession,
) -> Result<StartedSession, SessionError> {
    if response.version != crate::WORKER_PROTOCOL_VERSION {
        return Err(SessionError::WorkerProtocolFailed);
    }

    match response.message {
        WorkerResponse::Ready { session } if status.success() && session == expected => Ok(session),
        WorkerResponse::Ready { .. } => Err(SessionError::WorkerProtocolFailed),
        WorkerResponse::AuthenticationFailed if !status.success() => {
            Err(SessionError::AuthenticationFailed)
        }
        WorkerResponse::SessionFailed { .. } if !status.success() => {
            Err(SessionError::AuthenticatedSessionFailed)
        }
        WorkerResponse::Rejected { .. } if !status.success() => Err(SessionError::WorkerRejected),
        _ => Err(SessionError::WorkerProtocolFailed),
    }
}
