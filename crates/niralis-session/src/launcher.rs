use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::process::ExitStatus;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tempfile::{Builder, TempDir};
use tracing::debug;

use crate::{
    worker_attempt::WorkerAttempt, write_control_request, SessionError, SessionLauncher,
    SessionRequest, StartedSession, WorkerControlRequest, WorkerEnvelope, WorkerRequest,
    WorkerResponse, WorkerSecret,
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
        session_pgid: u32,
        worker_id: String,
        control_path: PathBuf,
        control_dir: TempDir,
    },
    Terminate {
        session: StartedSession,
        result: mpsc::Sender<Result<(), SessionError>>,
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
    session_pgid: u32,
    worker_id: String,
    control_path: PathBuf,
    _control_dir: TempDir,
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
                        session_pgid,
                        worker_id,
                        control_path,
                        control_dir,
                    }) => children.push(SupervisedWorker {
                        child,
                        session,
                        session_pid,
                        session_pgid,
                        worker_id,
                        control_path,
                        _control_dir: control_dir,
                    }),
                    Ok(WorkerSupervisorMessage::Terminate { session, result }) => {
                        let outcome = if let Some(worker) =
                            children.iter_mut().find(|worker| worker.session == session)
                        {
                            if worker.worker_id.is_empty() {
                                Err(SessionError::WorkerIoFailed)
                            } else {
                                match UnixStream::connect(&worker.control_path) {
                                    Ok(mut control) => write_control_request(
                                        &mut control,
                                        WorkerControlRequest::Terminate {
                                            worker_id: worker.worker_id.clone(),
                                            expected_worker_pid: worker.child.id(),
                                            expected_session_pid: worker.session_pid,
                                            expected_session_pgid: worker.session_pgid,
                                        },
                                    ),
                                    Err(_) => Err(SessionError::WorkerIoFailed),
                                }
                            }
                        } else {
                            Ok(())
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::Shutdown)
                    | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        for worker in &mut children {
                            if !worker.worker_id.is_empty() {
                                if let Ok(mut control) = UnixStream::connect(&worker.control_path) {
                                    let _ = write_control_request(
                                        &mut control,
                                        WorkerControlRequest::Terminate {
                                            worker_id: worker.worker_id.clone(),
                                            expected_worker_pid: worker.child.id(),
                                            expected_session_pid: worker.session_pid,
                                            expected_session_pgid: worker.session_pgid,
                                        },
                                    );
                                }
                            }
                        }
                        let deadline = Instant::now() + Duration::from_secs(6);
                        while !children.is_empty() && Instant::now() < deadline {
                            let mut index = 0;
                            while index < children.len() {
                                if children[index].child.try_wait().ok().flatten().is_some() {
                                    children.swap_remove(index);
                                } else {
                                    index += 1;
                                }
                            }
                            if !children.is_empty() {
                                thread::sleep(Duration::from_millis(25));
                            }
                        }
                        for worker in &mut children {
                            let _ = terminate_group(worker.session_pgid, libc::SIGKILL);
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
        session_pgid: u32,
        worker_id: String,
        control_path: PathBuf,
        control_dir: TempDir,
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
            session_pgid,
            worker_id,
            control_path,
            control_dir,
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

    fn terminate(&self, session: StartedSession) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::Terminate { session, result })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
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

    pub fn terminate_session(&self, session: StartedSession) -> Result<(), SessionError> {
        self.supervisor.terminate(session)
    }

    pub fn shutdown_sessions(&self) {
        let _ = self
            .supervisor
            .sender
            .send(WorkerSupervisorMessage::Shutdown);
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
                control_path: PathBuf::new(),
                worker_id: String::new(),
            },
            expected_started_session(&request),
        )
    }

    fn start_worker(
        &self,
        mut request: WorkerRequest,
        expected: StartedSession,
    ) -> Result<StartedSession, SessionError> {
        let (control_dir, control_path, worker_id) = create_control_endpoint()?;
        install_control_request(&mut request, control_path.clone(), worker_id.clone());
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
                    session_pgid,
                    fixture_version,
                    worker_id: started_worker_id,
                } if session == expected
                    && fixture_version == 1
                    && (started_worker_id == worker_id || started_worker_id.is_empty())
                    && session_pgid == session_pid =>
                {
                    if !attempt.is_alive()? {
                        return Err(SessionError::WorkerExitedAfterStart);
                    }
                    attempt.finish();
                    let child = attempt.take_child();
                    self.supervisor.register(
                        child,
                        expected.clone(),
                        session_pid,
                        session_pgid,
                        worker_id,
                        control_path,
                        control_dir,
                    )?;
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

fn create_control_endpoint() -> Result<(TempDir, PathBuf, String), SessionError> {
    let root = Path::new("/run/niralis/worker-control");
    let directory = if prepare_control_root(root).is_ok() {
        Builder::new()
            .prefix("worker-")
            .tempdir_in(root)
            .map_err(|_| SessionError::WorkerIoFailed)?
    } else {
        Builder::new()
            .prefix("niralis-worker-control-")
            .tempdir()
            .map_err(|_| SessionError::WorkerIoFailed)?
    };
    let worker_id = directory
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SessionError::WorkerIoFailed)?
        .to_owned();
    let path = directory.path().join("control.sock");
    Ok((directory, path, worker_id))
}

fn prepare_control_root(root: &Path) -> Result<(), SessionError> {
    fs::create_dir_all(root).map_err(|_| SessionError::WorkerIoFailed)?;
    let metadata = fs::symlink_metadata(root).map_err(|_| SessionError::WorkerIoFailed)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.gid() != 0 {
        return Err(SessionError::WorkerIoFailed);
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|_| SessionError::WorkerIoFailed)
}

fn install_control_request(request: &mut WorkerRequest, path: PathBuf, worker_id: String) {
    if let WorkerRequest::PamSession {
        control_path: control,
        worker_id: id,
        ..
    } = request
    {
        *control = path;
        *id = worker_id;
    }
}

fn terminate_group(pgid: u32, signal: i32) -> Result<(), SessionError> {
    if pgid == 0 || pgid > i32::MAX as u32 {
        return Err(SessionError::WorkerIoFailed);
    }
    let result = unsafe { libc::kill(-(pgid as libc::pid_t), signal) };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(SessionError::WorkerIoFailed)
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
