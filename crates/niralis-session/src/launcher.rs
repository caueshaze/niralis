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

        let mut stdin = child.stdin.take().ok_or(SessionError::WorkerIoFailed)?;
        if write_envelope(
            &mut stdin,
            WorkerRequest::PrepareSession {
                request: request.clone(),
            },
        )
        .is_err()
        {
            let _ = kill_and_reap(&mut child);
            return Err(SessionError::WorkerIoFailed);
        }
        drop(stdin);

        let stdout = child.stdout.take().ok_or(SessionError::WorkerIoFailed)?;
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut stdout = stdout;
            let result = read_envelope::<WorkerResponse, _>(&mut stdout);
            let _ = sender.send(result);
        });
        let deadline = Instant::now() + self.timeout;

        let response = match receiver.recv_timeout(remaining(deadline)?) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                kill_and_reap(&mut child);
                let _ = reader.join();
                return Err(SessionError::WorkerTimedOut);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = reap_child(&mut child);
                let _ = reader.join();
                return Err(SessionError::WorkerProtocolFailed);
            }
        }?;

        reader.join().map_err(|_| SessionError::WorkerIoFailed)?;
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

fn remaining(deadline: Instant) -> Result<Duration, SessionError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or(SessionError::WorkerTimedOut)
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
