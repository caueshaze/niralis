use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::{
    worker_io::{read_envelope, write_envelope},
    SessionError, SessionLauncher, SessionRequest, StartedSession, WorkerRequest, WorkerResponse,
    WorkerSecret,
};

#[derive(Debug, Clone)]
pub struct WorkerSessionLauncher {
    worker_path: PathBuf,
    timeout: Duration,
}

impl WorkerSessionLauncher {
    pub fn new(worker_path: PathBuf, timeout: Duration) -> Result<Self, SessionError> {
        if !worker_path.is_absolute() {
            return Err(SessionError::InvalidWorkerPath);
        }
        Ok(Self {
            worker_path,
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
        let mut child = spawn_worker(&self.worker_path)?;
        let stdin = child.stdin.take().ok_or(SessionError::WorkerIoFailed)?;
        let stdout = child.stdout.take().ok_or(SessionError::WorkerIoFailed)?;
        let (writer, writer_rx) = spawn_writer(stdin, request);
        let (reader, reader_rx) = spawn_reader(stdout);

        let writer_result = wait_thread_result(&writer_rx, deadline, &mut child)?;
        let response_result = wait_thread_result(&reader_rx, deadline, &mut child)?;
        let status_result = if response_result.is_ok() {
            Some(wait_for_exit(&mut child, deadline))
        } else {
            None
        };

        join_thread(writer);
        join_thread(reader);

        if !matches!(writer_result, Err(SessionError::WorkerIoFailed)) {
            writer_result?;
        }
        let response = response_result?;
        let status = status_result.ok_or(SessionError::WorkerProtocolFailed)??;
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

fn spawn_worker(worker_path: &Path) -> Result<Child, SessionError> {
    let child = Command::new(worker_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .env_clear()
        .current_dir("/")
        .spawn()
        .map_err(|_| SessionError::WorkerSpawnFailed)?;
    info!(path = %worker_path.display(), "spawned session worker");
    Ok(child)
}

fn spawn_writer(
    stdin: ChildStdin,
    request: WorkerRequest,
) -> (JoinHandle<()>, Receiver<Result<(), SessionError>>) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut stdin = stdin;
        let _ = sender.send(write_envelope(&mut stdin, request));
    });
    (handle, receiver)
}

fn spawn_reader(
    stdout: ChildStdout,
) -> (
    JoinHandle<()>,
    Receiver<Result<crate::WorkerEnvelope<WorkerResponse>, SessionError>>,
) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut stdout = stdout;
        let _ = sender.send(read_envelope::<WorkerResponse, _>(&mut stdout));
    });
    (handle, receiver)
}

fn wait_thread_result<T>(
    receiver: &Receiver<Result<T, SessionError>>,
    deadline: Instant,
    child: &mut Child,
) -> Result<Result<T, SessionError>, SessionError> {
    match receiver.recv_timeout(remaining(deadline)?) {
        Ok(result) => Ok(result),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            kill_and_reap(child);
            Err(SessionError::WorkerTimedOut)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = reap_child(child);
            Err(SessionError::WorkerIoFailed)
        }
    }
}

fn remaining(deadline: Instant) -> Result<Duration, SessionError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or(SessionError::WorkerTimedOut)
}

fn wait_for_exit(child: &mut Child, deadline: Instant) -> Result<ExitStatus, SessionError> {
    loop {
        if let Some(status) = child.try_wait().map_err(|_| SessionError::WorkerIoFailed)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            kill_and_reap(child);
            return Err(SessionError::WorkerTimedOut);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn map_response(
    response: crate::WorkerEnvelope<WorkerResponse>,
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

fn kill_and_reap(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) | Err(_) => {}
    }

    let _ = child.kill();
    let _ = reap_child(child);
}

fn reap_child(child: &mut Child) -> Result<(), SessionError> {
    child
        .wait()
        .map(|_| ())
        .map_err(|_| SessionError::WorkerIoFailed)
}

fn join_thread(handle: JoinHandle<()>) {
    let _ = handle.join();
}
