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
    types::RuntimeSessionId, worker_attempt::WorkerAttempt, write_control_request, SessionError,
    SessionLauncher, SessionRequest, StartedSession, WorkerControlRequest, WorkerEnvelope,
    WorkerRequest, WorkerResponse, WorkerSecret,
};

#[derive(Debug, Clone)]
pub struct WorkerSessionLauncher {
    worker_path: PathBuf,
    session_child_path: PathBuf,
    session_probe_path: PathBuf,
    timeout: Duration,
    worker_environment: Vec<(String, String)>,
    supervisor: Arc<WorkerSupervisor>,
    release_verifier: Arc<dyn crate::PayloadScopeReleaseVerifier>,
}

#[derive(Debug)]
enum WorkerSupervisorMessage {
    BeginPending {
        worker_id: String,
        worker_pid: u32,
        result: mpsc::Sender<Result<(), SessionError>>,
    },
    RecordPreparedScope {
        worker_id: String,
        worker_pid: u32,
        identity: crate::PayloadScopeIdentity,
        registration_nonce: String,
        result: mpsc::Sender<Result<(), SessionError>>,
    },
    BeginRelease {
        request: ReleaseRequest,
        result: mpsc::Sender<Result<ReleaseToken, SessionError>>,
    },
    CompleteRelease {
        token: ReleaseToken,
        verification: crate::ScopeReleaseVerification,
        result: mpsc::Sender<Result<(), SessionError>>,
    },
    AbortPending {
        worker_id: String,
    },
    Register {
        runtime_id: RuntimeSessionId,
        child: Child,
        session: StartedSession,
        session_pid: u32,
        session_pgid: u32,
        worker_id: String,
        logind_session_id: crate::LogindSessionId,
        payload_scope: crate::PayloadScopeIdentity,
        control_path: PathBuf,
        control_dir: TempDir,
        result: mpsc::Sender<Result<(), SessionError>>,
    },
    Terminate {
        session: StartedSession,
        runtime_id: Option<RuntimeSessionId>,
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
    ownership: RuntimeOwnership,
    child: Child,
    session: StartedSession,
    session_pid: u32,
    session_pgid: u32,
    worker_id: String,
    control_path: PathBuf,
    _control_dir: TempDir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeOwnership {
    runtime_id: RuntimeSessionId,
    logind_session_id: crate::LogindSessionId,
    payload_scope: crate::PayloadScopeIdentity,
}

struct PendingWorkerLifecycle {
    worker_id: String,
    worker_pid: u32,
    payload_scope: Option<crate::PayloadScopeIdentity>,
    registration_nonce: Option<String>,
    release_nonce: Option<String>,
    generation: u64,
    recovery_required: Option<crate::PayloadScopeRecoveryReason>,
    terminal_before_started: bool,
}

#[derive(Debug, Clone)]
struct ReleaseRequest {
    worker_id: String,
    worker_pid: u32,
    registration_nonce: String,
    release_nonce: String,
    identity: crate::PayloadScopeIdentity,
}

#[derive(Debug, Clone)]
struct ReleaseToken {
    worker_id: String,
    worker_pid: u32,
    registration_nonce: String,
    release_nonce: String,
    identity: crate::PayloadScopeIdentity,
    generation: u64,
}

#[derive(Debug)]
enum PendingLaunchPhase {
    Spawned,
    Preparing,
    ScopeRegistered {
        identity: crate::PayloadScopeIdentity,
        registration_nonce: String,
    },
}

struct PendingSupervisorGuard {
    supervisor: Arc<WorkerSupervisor>,
    worker_id: String,
}

impl Drop for PendingSupervisorGuard {
    fn drop(&mut self) {
        self.supervisor.abort_pending(&self.worker_id);
    }
}

impl WorkerSupervisor {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || {
            let mut children: Vec<SupervisedWorker> = Vec::new();
            let mut pending: Vec<PendingWorkerLifecycle> = Vec::new();
            loop {
                match receiver.recv_timeout(Duration::from_millis(25)) {
                    Ok(WorkerSupervisorMessage::BeginPending {
                        worker_id,
                        worker_pid,
                        result,
                    }) => {
                        let outcome = if worker_id.is_empty()
                            || pending.iter().any(|entry| entry.worker_id == worker_id)
                        {
                            Err(SessionError::WorkerProtocolFailed)
                        } else {
                            pending.push(PendingWorkerLifecycle {
                                worker_id,
                                worker_pid,
                                payload_scope: None,
                                registration_nonce: None,
                                release_nonce: None,
                                generation: 0,
                                recovery_required: None,
                                terminal_before_started: false,
                            });
                            Ok(())
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::RecordPreparedScope {
                        worker_id,
                        worker_pid,
                        identity,
                        registration_nonce,
                        result,
                    }) => {
                        let outcome = match pending.iter_mut().find(|entry| {
                            entry.worker_id == worker_id && entry.worker_pid == worker_pid
                        }) {
                            Some(entry)
                                if !entry.terminal_before_started
                                    && entry.recovery_required.is_none()
                                    && entry.release_nonce.is_none()
                                    && entry
                                        .payload_scope
                                        .as_ref()
                                        .is_none_or(|existing| existing == &identity) =>
                            {
                                entry.payload_scope = Some(identity);
                                entry.registration_nonce = Some(registration_nonce);
                                entry.generation = entry.generation.wrapping_add(1);
                                Ok(())
                            }
                            _ => Err(SessionError::WorkerProtocolFailed),
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::BeginRelease { request, result }) => {
                        let outcome = match pending.iter_mut().find(|entry| {
                            entry.worker_id == request.worker_id
                                && entry.worker_pid == request.worker_pid
                        }) {
                            Some(entry)
                                if !entry.terminal_before_started
                                    && entry.recovery_required.is_none()
                                    && entry.payload_scope.as_ref() == Some(&request.identity)
                                    && entry.registration_nonce.as_deref()
                                        == Some(&request.registration_nonce)
                                    && entry
                                        .release_nonce
                                        .as_ref()
                                        .is_none_or(|nonce| nonce == &request.release_nonce) =>
                            {
                                entry.release_nonce = Some(request.release_nonce.clone());
                                entry.generation = entry.generation.wrapping_add(1);
                                Ok(ReleaseToken {
                                    worker_id: request.worker_id,
                                    worker_pid: request.worker_pid,
                                    registration_nonce: request.registration_nonce,
                                    release_nonce: request.release_nonce,
                                    identity: request.identity,
                                    generation: entry.generation,
                                })
                            }
                            _ => Err(SessionError::WorkerProtocolFailed),
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::CompleteRelease {
                        token,
                        verification,
                        result,
                    }) => {
                        let index = pending.iter().position(|entry| {
                            entry.worker_id == token.worker_id
                                && entry.worker_pid == token.worker_pid
                                && entry.generation == token.generation
                                && entry.payload_scope.as_ref() == Some(&token.identity)
                                && entry.registration_nonce.as_deref()
                                    == Some(&token.registration_nonce)
                                && entry.release_nonce.as_deref() == Some(&token.release_nonce)
                        });
                        let outcome = match (index, verification) {
                            (Some(index), crate::ScopeReleaseVerification::Released) => {
                                pending.swap_remove(index);
                                Ok(())
                            }
                            (
                                Some(index),
                                crate::ScopeReleaseVerification::RecoveryRequired(reason),
                            ) => {
                                pending[index].recovery_required = Some(reason);
                                pending[index].terminal_before_started = true;
                                Ok(())
                            }
                            _ => Err(SessionError::WorkerProtocolFailed),
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::AbortPending { worker_id }) => {
                        if let Some(index) = pending
                            .iter()
                            .position(|entry| entry.worker_id == worker_id)
                        {
                            if pending[index].payload_scope.is_some() {
                                pending[index].terminal_before_started = true;
                                let reason = pending[index].recovery_required.get_or_insert(
                                    crate::PayloadScopeRecoveryReason::VerificationUnavailable,
                                );
                                tracing::warn!(?reason, worker_id, "worker died with acknowledged payload scope still registered; recovery required");
                            } else {
                                pending.swap_remove(index);
                            }
                        }
                    }
                    Ok(WorkerSupervisorMessage::Register {
                        runtime_id,
                        child,
                        session,
                        session_pid,
                        session_pgid,
                        worker_id,
                        logind_session_id,
                        payload_scope,
                        control_path,
                        control_dir,
                        result,
                    }) => {
                        let index = pending.iter().position(|entry| {
                            entry.worker_id == worker_id
                                && entry.worker_pid == child.id()
                                && entry.payload_scope.as_ref() == Some(&payload_scope)
                                && entry.release_nonce.is_none()
                                && entry.recovery_required.is_none()
                                && !entry.terminal_before_started
                        });
                        if let Some(index) = index {
                            pending.swap_remove(index);
                            children.push(SupervisedWorker {
                                ownership: RuntimeOwnership {
                                    runtime_id,
                                    logind_session_id,
                                    payload_scope,
                                },
                                child,
                                session,
                                session_pid,
                                session_pgid,
                                worker_id,
                                control_path,
                                _control_dir: control_dir,
                            });
                            let _ = result.send(Ok(()));
                        } else {
                            let mut child = child;
                            let _ = child.kill();
                            let _ = child.wait();
                            let _ = result.send(Err(SessionError::WorkerProtocolFailed));
                        }
                    }
                    Ok(WorkerSupervisorMessage::Terminate {
                        session,
                        runtime_id,
                        result,
                    }) => {
                        let outcome = if let Some(worker) = children.iter_mut().find(|worker| {
                            runtime_id.as_ref().map_or(worker.session == session, |id| {
                                worker.ownership.runtime_id == *id
                            })
                        }) {
                            request_worker_termination(worker)
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
                            debug!(?status, username = %children[index].session.username, session_pid = children[index].session_pid, logind_session_id = %children[index].ownership.logind_session_id.as_str(), "session worker exited and was reaped; runtime/logind ownership removed");
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

    fn begin_pending(&self, worker_id: &str, worker_pid: u32) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::BeginPending {
                worker_id: worker_id.to_owned(),
                worker_pid,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn record_prepared_scope(
        &self,
        worker_id: &str,
        worker_pid: u32,
        identity: crate::PayloadScopeIdentity,
        registration_nonce: String,
    ) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::RecordPreparedScope {
                worker_id: worker_id.to_owned(),
                worker_pid,
                identity,
                registration_nonce,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn begin_release(&self, request: ReleaseRequest) -> Result<ReleaseToken, SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::BeginRelease { request, result })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn complete_release(
        &self,
        token: ReleaseToken,
        verification: crate::ScopeReleaseVerification,
    ) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::CompleteRelease {
                token,
                verification,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn abort_pending(&self, worker_id: &str) {
        let _ = self.sender.send(WorkerSupervisorMessage::AbortPending {
            worker_id: worker_id.to_owned(),
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn register(
        &self,
        child: Child,
        session: StartedSession,
        session_pid: u32,
        session_pgid: u32,
        worker_id: String,
        logind_session_id: crate::LogindSessionId,
        payload_scope: crate::PayloadScopeIdentity,
        control_path: PathBuf,
        control_dir: TempDir,
    ) -> Result<RuntimeSessionId, SessionError> {
        let mut child = child;
        if child
            .try_wait()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .is_some()
        {
            return Err(SessionError::WorkerExitedAfterStart);
        }
        let runtime_id = RuntimeSessionId::new(worker_id.clone());
        let (result, receiver) = mpsc::channel();
        match self.sender.send(WorkerSupervisorMessage::Register {
            runtime_id: runtime_id.clone(),
            child,
            session,
            session_pid,
            session_pgid,
            worker_id,
            logind_session_id,
            payload_scope,
            control_path,
            control_dir,
            result,
        }) {
            Ok(()) => {
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| SessionError::WorkerIoFailed)??;
                Ok(runtime_id)
            }
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
            .send(WorkerSupervisorMessage::Terminate {
                session,
                runtime_id: None,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    #[cfg(any(test, feature = "integration-test-control"))]
    fn terminate_runtime(&self, runtime_id: RuntimeSessionId) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::Terminate {
                session: StartedSession {
                    username: String::new(),
                    session: niralis_protocol::SessionInfo {
                        id: String::new(),
                        name: String::new(),
                        kind: niralis_protocol::SessionKind::Wayland,
                    },
                },
                runtime_id: Some(runtime_id),
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }
}

fn request_worker_termination(worker: &mut SupervisedWorker) -> Result<(), SessionError> {
    if worker.worker_id.is_empty() {
        return Err(SessionError::WorkerIoFailed);
    }

    if worker
        .child
        .try_wait()
        .map_err(|_| SessionError::WorkerIoFailed)?
        .is_some()
    {
        return Ok(());
    }

    let mut control = match UnixStream::connect(&worker.control_path) {
        Ok(control) => control,
        Err(_) => {
            return if worker
                .child
                .try_wait()
                .map_err(|_| SessionError::WorkerIoFailed)?
                .is_some()
            {
                Ok(())
            } else {
                Err(SessionError::WorkerIoFailed)
            }
        }
    };

    let result = write_control_request(
        &mut control,
        WorkerControlRequest::Terminate {
            worker_id: worker.worker_id.clone(),
            expected_worker_pid: worker.child.id(),
            expected_session_pid: worker.session_pid,
            expected_session_pgid: worker.session_pgid,
        },
    );

    if result.is_ok() {
        return Ok(());
    }

    if worker
        .child
        .try_wait()
        .map_err(|_| SessionError::WorkerIoFailed)?
        .is_some()
    {
        Ok(())
    } else {
        result
    }
}

fn peer_matches(stream: &UnixStream, expected_uid: u32, expected_pid: u32) -> bool {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            std::os::fd::AsRawFd::as_raw_fd(stream),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        )
    };
    result == 0 && credentials.uid == expected_uid && credentials.pid as u32 == expected_pid
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
        worker_environment: Vec<(String, String)>,
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
            worker_environment,
            supervisor: Arc::new(WorkerSupervisor::new()),
            release_verifier: Arc::new(crate::SystemdPayloadScopeReleaseVerifier),
        })
    }

    #[cfg(any(test, feature = "integration-test-control"))]
    pub fn set_payload_scope_release_verifier_for_test(
        &mut self,
        verifier: Arc<dyn crate::PayloadScopeReleaseVerifier>,
    ) {
        self.release_verifier = verifier;
    }

    pub fn worker_path(&self) -> &Path {
        &self.worker_path
    }

    pub fn terminate_session(&self, session: StartedSession) -> Result<(), SessionError> {
        self.supervisor.terminate(session)
    }

    #[cfg(any(test, feature = "integration-test-control"))]
    pub fn terminate_runtime_session_for_test(
        &self,
        runtime_id: RuntimeSessionId,
    ) -> Result<(), SessionError> {
        self.supervisor.terminate_runtime(runtime_id)
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
        launch_plan: crate::SessionExecPlan,
        pam_service: String,
        password: WorkerSecret,
    ) -> Result<StartedSession, SessionError> {
        self.start_worker(
            WorkerRequest::PamSession {
                request: request.clone(),
                launch_plan,
                pam_service,
                password,
                session_child_path: self.session_child_path.clone(),
                session_probe_path: self.session_probe_path.clone(),
                control_path: PathBuf::new(),
                worker_id: String::new(),
                launcher_pid: 0,
            },
            expected_started_session(&request),
            true,
        )
        .map(|(session, _)| session)
    }

    #[cfg(any(test, feature = "integration-test-control"))]
    pub fn start_pam_session_for_test(
        &self,
        request: SessionRequest,
        launch_plan: crate::SessionExecPlan,
        pam_service: String,
        password: WorkerSecret,
    ) -> Result<(StartedSession, RuntimeSessionId), SessionError> {
        self.start_worker(
            WorkerRequest::PamSession {
                request: request.clone(),
                launch_plan,
                pam_service,
                password,
                session_child_path: self.session_child_path.clone(),
                session_probe_path: self.session_probe_path.clone(),
                control_path: PathBuf::new(),
                worker_id: String::new(),
                launcher_pid: 0,
            },
            expected_started_session(&request),
            true,
        )
    }

    fn start_worker(
        &self,
        mut request: WorkerRequest,
        expected: StartedSession,
        install_control: bool,
    ) -> Result<(StartedSession, RuntimeSessionId), SessionError> {
        let (control_dir, control_path, worker_id) = create_control_endpoint()?;
        let requires_pending_lifecycle = matches!(&request, WorkerRequest::PamSession { .. });
        if install_control {
            install_control_request(&mut request, control_path.clone(), worker_id.clone());
        }
        let deadline = Instant::now() + self.timeout;
        let mut attempt =
            WorkerAttempt::spawn(&self.worker_path, &self.worker_environment, request)?;
        let worker_pid = attempt.child_id();
        let _pending_guard = if requires_pending_lifecycle {
            self.supervisor.begin_pending(&worker_id, worker_pid)?;
            Some(PendingSupervisorGuard {
                supervisor: self.supervisor.clone(),
                worker_id: worker_id.clone(),
            })
        } else {
            None
        };
        let mut phase = PendingLaunchPhase::Spawned;
        let writer_result = attempt.wait_writer(deadline);
        let response_result = loop {
            let event = attempt.wait_reader(deadline);
            match event {
                Ok(response) if response.version != crate::WORKER_PROTOCOL_VERSION => {
                    break Err(SessionError::WorkerProtocolFailed);
                }
                Ok(WorkerEnvelope {
                    message:
                        WorkerResponse::Preparing {
                            worker_id: event_worker_id,
                        },
                    ..
                }) => {
                    if !matches!(phase, PendingLaunchPhase::Spawned) || event_worker_id != worker_id
                    {
                        break Err(SessionError::WorkerProtocolFailed);
                    }
                    phase = PendingLaunchPhase::Preparing;
                }
                Ok(WorkerEnvelope {
                    message:
                        WorkerResponse::PayloadScopePrepared {
                            worker_id: event_worker_id,
                            expected_worker_pid,
                            session_pid: _,
                            registration_nonce,
                            scope_identity,
                        },
                    ..
                }) => {
                    if !matches!(phase, PendingLaunchPhase::Preparing)
                        || event_worker_id != worker_id
                        || expected_worker_pid != worker_pid
                        || registration_nonce.is_empty()
                        || registration_nonce.len() > 128
                        || !scope_identity.validate()
                    {
                        break Err(SessionError::WorkerProtocolFailed);
                    }
                    self.supervisor.record_prepared_scope(
                        &worker_id,
                        worker_pid,
                        scope_identity.clone(),
                        registration_nonce.clone(),
                    )?;
                    // Persisted before acknowledging it. No registry lock is
                    // held while performing socket I/O.
                    phase = PendingLaunchPhase::ScopeRegistered {
                        identity: scope_identity,
                        registration_nonce: registration_nonce.clone(),
                    };
                    let mut control = match UnixStream::connect(&control_path) {
                        Ok(control) => control,
                        Err(_) => break Err(SessionError::WorkerIoFailed),
                    };
                    if write_control_request(
                        &mut control,
                        WorkerControlRequest::PayloadScopeRegistered {
                            worker_id: worker_id.clone(),
                            expected_worker_pid: worker_pid,
                            registration_nonce,
                        },
                    )
                    .is_err()
                    {
                        break Err(SessionError::WorkerIoFailed);
                    }
                }
                Ok(WorkerEnvelope {
                    message:
                        WorkerResponse::PayloadScopeReleaseReady {
                            worker_id: event_worker_id,
                        },
                    ..
                }) => {
                    let (identity, registration_nonce) = match &phase {
                        PendingLaunchPhase::ScopeRegistered {
                            identity,
                            registration_nonce,
                        } if event_worker_id == worker_id => {
                            (identity.clone(), registration_nonce.clone())
                        }
                        _ => break Err(SessionError::WorkerProtocolFailed),
                    };
                    let mut control = match UnixStream::connect(&control_path) {
                        Ok(control) => control,
                        Err(_) => break Err(SessionError::WorkerIoFailed),
                    };
                    if !peer_matches(&control, 0, worker_pid) {
                        break Err(SessionError::WorkerProtocolFailed);
                    }
                    let request = match crate::read_control_request(&mut control) {
                        Ok(request)
                            if request.version == crate::WORKER_CONTROL_PROTOCOL_VERSION =>
                        {
                            request.message
                        }
                        _ => break Err(SessionError::WorkerProtocolFailed),
                    };
                    let (release_nonce, local_cleanup_succeeded) = match request {
                        WorkerControlRequest::PayloadScopeReleaseRequested {
                            worker_id: requested_worker_id,
                            expected_worker_pid,
                            registration_nonce: requested_registration_nonce,
                            release_nonce,
                            scope_identity,
                            local_cleanup_succeeded,
                        } if requested_worker_id == worker_id
                            && expected_worker_pid == worker_pid
                            && requested_registration_nonce == registration_nonce
                            && scope_identity == identity
                            && !release_nonce.is_empty()
                            && release_nonce.len() <= 128 =>
                        {
                            (release_nonce, local_cleanup_succeeded)
                        }
                        _ => break Err(SessionError::WorkerProtocolFailed),
                    };
                    debug!(
                        local_cleanup_succeeded,
                        "payload scope release requested; supervisor verifying registered scope"
                    );
                    let token = self.supervisor.begin_release(ReleaseRequest {
                        worker_id: worker_id.clone(),
                        worker_pid,
                        registration_nonce: registration_nonce.clone(),
                        release_nonce: release_nonce.clone(),
                        identity: identity.clone(),
                    })?;
                    let verification = self.release_verifier.verify(&identity, deadline);
                    self.supervisor
                        .complete_release(token, verification.clone())?;
                    let response = match verification {
                        crate::ScopeReleaseVerification::Released => {
                            debug!(unit = %identity.unit_name, "payload scope release acknowledged");
                            WorkerControlRequest::PayloadScopeReleased {
                                worker_id: worker_id.clone(),
                                expected_worker_pid: worker_pid,
                                registration_nonce,
                                release_nonce,
                            }
                        }
                        crate::ScopeReleaseVerification::RecoveryRequired(reason) => {
                            debug!(?reason, unit = %identity.unit_name, "payload scope cleanup could not be proven; lifecycle marked recovery required");
                            WorkerControlRequest::PayloadScopeRecoveryRequired {
                                worker_id: worker_id.clone(),
                                expected_worker_pid: worker_pid,
                                registration_nonce,
                                release_nonce,
                                reason,
                            }
                        }
                    };
                    if write_control_request(&mut control, response).is_err() {
                        break Err(SessionError::WorkerIoFailed);
                    }
                }
                terminal => break terminal,
            }
        };
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
                    logind_session_id,
                } if session == expected
                    && matches!(fixture_version, 1 | 2)
                    && (started_worker_id == worker_id || started_worker_id.is_empty())
                    && session_pgid == session_pid =>
                {
                    let payload_scope = if let PendingLaunchPhase::ScopeRegistered {
                        identity,
                        registration_nonce,
                    } = &phase
                    {
                        debug!(unit = %identity.unit_name, nonce_len = registration_nonce.len(), "promoting pre-Started payload scope registration");
                        if identity.logind_session_id != logind_session_id {
                            return Err(SessionError::WorkerProtocolFailed);
                        }
                        identity.clone()
                    } else {
                        return Err(SessionError::WorkerProtocolFailed);
                    };
                    if !attempt.is_alive()? {
                        return Err(SessionError::WorkerExitedAfterStart);
                    }
                    attempt.finish();
                    let child = attempt.take_child();
                    let runtime_id = self.supervisor.register(
                        child,
                        expected.clone(),
                        session_pid,
                        session_pgid,
                        worker_id,
                        logind_session_id,
                        payload_scope,
                        control_path,
                        control_dir,
                    )?;
                    return Ok((expected, runtime_id));
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
            .map(|session| (session, RuntimeSessionId::new("completed".to_owned())))
    }
}

impl SessionLauncher for WorkerSessionLauncher {
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError> {
        self.start_worker(
            WorkerRequest::PrepareSession {
                request: request.clone(),
            },
            expected_started_session(&request),
            true,
        )
        .map(|(session, _)| session)
    }
}

fn expected_started_session(request: &SessionRequest) -> StartedSession {
    StartedSession {
        username: request.username.clone(),
        session: request.session.clone(),
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    fn ownership(runtime: &str, logind: &str) -> RuntimeOwnership {
        RuntimeOwnership {
            runtime_id: RuntimeSessionId::new(runtime.to_owned()),
            logind_session_id: crate::LogindSessionId::new(logind.to_owned()).unwrap(),
            payload_scope: crate::PayloadScopeIdentity {
                unit_name: format!("niralis-payload-{runtime}.scope"),
                invocation_id: "0123456789abcdef0123456789abcdef".into(),
                expected_uid: 1000,
                logind_session_id: crate::LogindSessionId::new(logind.to_owned()).unwrap(),
            },
        }
    }

    #[test]
    fn swap_remove_removes_only_the_matching_runtime_logind_pair() {
        let a = ownership("runtime-a", "c1");
        let b = ownership("runtime-b", "c2");
        let mut active = vec![a.clone(), b.clone()];
        let index = active
            .iter()
            .position(|value| value.runtime_id == a.runtime_id)
            .unwrap();
        let removed = active.swap_remove(index);
        assert_eq!(removed, a);
        assert_eq!(active, vec![b]);
    }

    #[test]
    fn expired_runtime_id_cannot_match_a_future_ownership() {
        let expired = ownership("runtime-a", "c1");
        let future = ownership("runtime-b", "c2");
        assert_ne!(expired.runtime_id, future.runtime_id);
        assert_ne!(expired.logind_session_id, future.logind_session_id);
    }

    fn identity() -> crate::PayloadScopeIdentity {
        crate::PayloadScopeIdentity {
            unit_name: "niralis-payload-release-test.scope".into(),
            invocation_id: "0123456789abcdef0123456789abcdef".into(),
            expected_uid: 1000,
            logind_session_id: crate::LogindSessionId::new("c1".into()).unwrap(),
        }
    }

    fn registered_supervisor() -> (WorkerSupervisor, crate::PayloadScopeIdentity) {
        let supervisor = WorkerSupervisor::new();
        supervisor.begin_pending("worker-release", 4242).unwrap();
        let scope = identity();
        supervisor
            .record_prepared_scope("worker-release", 4242, scope.clone(), "reg-1".into())
            .unwrap();
        (supervisor, scope)
    }

    #[test]
    fn release_verification_removes_only_matching_registered_lifecycle() {
        let (supervisor, scope) = registered_supervisor();
        let token = supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: scope,
            })
            .unwrap();
        supervisor
            .complete_release(token, crate::ScopeReleaseVerification::Released)
            .unwrap();
        assert!(supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: identity(),
            })
            .is_err());
    }

    #[test]
    fn failed_release_verification_retains_recovery_state() {
        let (supervisor, scope) = registered_supervisor();
        let token = supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: scope,
            })
            .unwrap();
        supervisor
            .complete_release(
                token,
                crate::ScopeReleaseVerification::RecoveryRequired(
                    crate::PayloadScopeRecoveryReason::MembershipNotEmpty,
                ),
            )
            .unwrap();
        assert!(supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: identity(),
            })
            .is_err());
    }

    #[test]
    fn divergent_release_identity_is_rejected() {
        let (supervisor, _) = registered_supervisor();
        let mut other = identity();
        other.invocation_id = "fedcba9876543210fedcba9876543210".into();
        assert!(supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: other,
            })
            .is_err());
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
        launcher_pid,
        ..
    } = request
    {
        *control = path;
        *id = worker_id;
        *launcher_pid = std::process::id();
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
        WorkerResponse::SessionFailed { code } if !status.success() => {
            debug!(
                ?code,
                "session worker reported authenticated session failure"
            );
            Err(SessionError::AuthenticatedSessionFailed)
        }
        WorkerResponse::Rejected { code } if !status.success() => {
            debug!(?code, "session worker rejected request");
            Err(SessionError::WorkerRejected)
        }
        _ => Err(SessionError::WorkerProtocolFailed),
    }
}
