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
        supervisor_channel: UnixStream,
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
    _supervisor_channel: UnixStream,
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

