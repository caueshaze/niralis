use std::path::{Path, PathBuf};
use std::process::Child;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use crate::{
    worker_io::{read_envelope, write_envelope},
    SessionError, SessionLauncher, SessionRequest, StartedSession, WorkerRequest, WorkerResponse,
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
}

impl SessionLauncher for WorkerSessionLauncher {
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError> {
        let expected = StartedSession {
            username: request.username.clone(),
            session: request.session.clone(),
        };
        let mut child = Command::new(&self.worker_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env_clear()
            .current_dir("/")
            .spawn()
            .map_err(|_| SessionError::WorkerSpawnFailed)?;
        info!(path = %self.worker_path.display(), "spawned session worker");

        let deadline = Instant::now() + self.timeout;
        let stdin = child.stdin.take().ok_or(SessionError::WorkerIoFailed)?;
        let stdout = child.stdout.take().ok_or(SessionError::WorkerIoFailed)?;
        let writer = spawn_writer(stdin, request.clone());
        let reader = spawn_reader(stdout);

        let _ = await_worker_result(writer, deadline, &mut child)?;
        let response = await_worker_result(reader, deadline, &mut child)??;
        let status = wait_for_exit(&mut child, deadline)?;
        debug!(?status, "session worker exited");
        if response.version != crate::WORKER_PROTOCOL_VERSION {
            return Err(SessionError::WorkerProtocolFailed);
        }

        match response.message {
            WorkerResponse::Ready { session } if status.success() && session == expected => {
                Ok(session)
            }
            WorkerResponse::Ready { .. } => Err(SessionError::WorkerProtocolFailed),
            WorkerResponse::Rejected { .. } => Err(SessionError::WorkerRejected),
        }
    }
}

fn spawn_writer(
    stdin: std::process::ChildStdin,
    request: SessionRequest,
) -> thread::JoinHandle<Result<(), SessionError>> {
    thread::spawn(move || {
        let mut stdin = stdin;
        write_envelope(&mut stdin, WorkerRequest::PrepareSession { request })
    })
}

fn spawn_reader(
    stdout: std::process::ChildStdout,
) -> thread::JoinHandle<Result<crate::WorkerEnvelope<WorkerResponse>, SessionError>> {
    thread::spawn(move || {
        let mut stdout = stdout;
        read_envelope::<WorkerResponse, _>(&mut stdout)
    })
}

fn remaining(deadline: Instant) -> Result<Duration, SessionError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or(SessionError::WorkerTimedOut)
}

fn await_worker_result<T: Send + 'static>(
    handle: thread::JoinHandle<Result<T, SessionError>>,
    deadline: Instant,
    child: &mut Child,
) -> Result<Result<T, SessionError>, SessionError> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(handle.join());
    });

    match receiver.recv_timeout(remaining(deadline)?) {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => {
            let _ = kill_and_reap(child);
            Err(SessionError::WorkerIoFailed)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = kill_and_reap(child);
            Err(SessionError::WorkerTimedOut)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = reap_child(child);
            Err(SessionError::WorkerProtocolFailed)
        }
    }
}

fn wait_for_exit(
    child: &mut Child,
    deadline: Instant,
) -> Result<std::process::ExitStatus, SessionError> {
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

fn kill_and_reap(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(_) => {}
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
