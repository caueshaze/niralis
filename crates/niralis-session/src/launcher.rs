use std::path::{Path, PathBuf};
use std::process::Child;
use std::process::ExitStatus;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
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
    session_probe_path: PathBuf,
    timeout: Duration,
    supervisor: Arc<WorkerSupervisor>,
}

#[derive(Debug)]
enum WorkerSupervisorMessage {
    Register {
        child: Child,
        session: StartedSession,
        session_pid: u32,
    },
    Shutdown,
}

#[derive(Debug)]
struct WorkerSupervisor {
    sender: mpsc::Sender<WorkerSupervisorMessage>,
    join: Mutex<Option<JoinHandle<()>>>,
}

struct SupervisedWorker {
    child: Child,
    session: StartedSession,
    session_pid: u32,
}

impl WorkerSupervisor {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || {
            let mut children: Vec<SupervisedWorker> = Vec::new();
            loop {
                match receiver.recv_timeout(Duration::from_millis(25)) {
                    Ok(WorkerSupervisorMessage::Register {
                        child,
                        session,
                        session_pid,
                    }) => children.push(SupervisedWorker {
                        child,
                        session,
                        session_pid,
                    }),
                    Ok(WorkerSupervisorMessage::Shutdown)
                    | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        for worker in &mut children {
                            let _ = worker.child.kill();
                            let _ = worker.child.wait();
                        }
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                let mut index = 0;
                while index < children.len() {
                    match children[index].child.try_wait() {
                        Ok(Some(status)) => {
                            debug!(?status, username = %children[index].session.username, session_pid = children[index].session_pid, "session worker exited and was reaped");
                            children.swap_remove(index);
                        }
                        Ok(None) => index += 1,
                        Err(error) => {
                            debug!(?error, "failed to inspect session worker");
                            index += 1;
                        }
                    }
                }
            }
        });
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }

    fn register(
        &self,
        child: Child,
        session: StartedSession,
        session_pid: u32,
    ) -> Result<(), SessionError> {
        let mut child = child;
        if child
            .try_wait()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .is_some()
        {
            return Err(SessionError::WorkerExitedAfterStart);
        }
        match self.sender.send(WorkerSupervisorMessage::Register {
            child,
            session,
            session_pid,
        }) {
            Ok(()) => Ok(()),
            Err(error) => {
                if let WorkerSupervisorMessage::Register { mut child, .. } = error.0 {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(SessionError::WorkerIoFailed)
            }
        }
    }
}

impl Drop for WorkerSupervisor {
    fn drop(&mut self) {
        let _ = self.sender.send(WorkerSupervisorMessage::Shutdown);
        if let Ok(mut join) = self.join.lock() {
            if let Some(handle) = join.take() {
                let _ = handle.join();
            }
        }
    }
}

impl WorkerSessionLauncher {
    pub fn new(
        worker_path: PathBuf,
        session_child_path: PathBuf,
        session_probe_path: PathBuf,
        timeout: Duration,
    ) -> Result<Self, SessionError> {
        if !worker_path.is_absolute()
            || !session_child_path.is_absolute()
            || !session_probe_path.is_absolute()
        {
            return Err(SessionError::InvalidWorkerPath);
        }
        Ok(Self {
            worker_path,
            session_child_path,
            session_probe_path,
            timeout,
            supervisor: Arc::new(WorkerSupervisor::new()),
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
                session_probe_path: self.session_probe_path.clone(),
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
        let started_response = response_result
            .as_ref()
            .ok()
            .and_then(|response| match &response.message {
                WorkerResponse::Started { .. } => Some(()),
                _ => None,
            })
            .is_some();
        if started_response {
            writer_result?;
            let response = response_result?;
            match response.message {
                WorkerResponse::Started {
                    session,
                    session_pid,
                    fixture_version,
                } if session == expected && fixture_version == 1 => {
                    if !attempt.is_alive()? {
                        return Err(SessionError::WorkerExitedAfterStart);
                    }
                    attempt.finish();
                    let child = attempt.take_child();
                    self.supervisor
                        .register(child, expected.clone(), session_pid)?;
                    return Ok(expected);
                }
                WorkerResponse::Started { .. } => return Err(SessionError::WorkerProtocolFailed),
                _ => unreachable!(),
            }
        }
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
        WorkerResponse::Started { .. } => Err(SessionError::WorkerProtocolFailed),
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
