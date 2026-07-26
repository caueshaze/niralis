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
    #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    fixture_supervisor_transport: bool,
    #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    fixture_inherited_supervisor_control: bool,
    #[cfg(any(feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    fixture_recovery_provider: Option<Arc<SupervisorFixtureRecoveryProvider>>,
}

#[derive(Debug)]
enum WorkerSupervisorMessage {
    ReserveSeat {
        lifecycle_id: String,
        result: mpsc::Sender<Result<supervisor_loop::admission::AdmissionLease, SessionError>>,
    },
    CancelAdmission {
        lease: supervisor_loop::admission::AdmissionRollbackLease,
    },
    BeginPending {
        lease: supervisor_loop::admission::AdmissionLease,
        worker_pid: u32,
        launcher_pid: u32,
        session: StartedSession,
        child: Arc<Mutex<Child>>,
        result: mpsc::Sender<Result<supervisor_loop::admission::PendingLifecycleLease, SessionError>>,
    },
    RecordPreparedScope {
        worker_id: String,
        worker_pid: u32,
        session_pid: u32,
        identity: crate::PayloadScopeIdentity,
        registration_nonce: String,
        result: mpsc::Sender<Result<(), SessionError>>,
    },
    MarkPayloadRegistered {
        worker_id: String,
        worker_pid: u32,
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
        lease: supervisor_loop::admission::PendingLifecycleLease,
        expected_clean: bool,
        worker_exit_status: Option<ExitStatus>,
        result: mpsc::Sender<Result<(), SessionError>>,
    },
    Register {
        admission_transaction: Box<login_transaction::PendingLaunchTransaction>,
        runtime_id: RuntimeSessionId,
        supervisor_channel: UnixStream,
        #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
        fixture_supervisor_transport: Option<worker_attempt::FixtureSupervisorTransportHandle>,
        #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
        fixture_inherited_supervisor_control: bool,
        session: StartedSession,
        session_pid: u32,
        session_pgid: u32,
        worker_id: String,
        logind_session_id: crate::LogindSessionId,
        payload_scope: crate::PayloadScopeIdentity,
        registration_nonce: String,
        control_path: PathBuf,
        control_dir: TempDir,
        control_sender: mpsc::Sender<WorkerSupervisorMessage>,
        result: mpsc::Sender<Result<(), SessionError>>,
    },
    TerminalVtIntent {
        worker_id: String,
        worker_pid: u32,
        registration_nonce: String,
        identity: crate::PayloadScopeIdentity,
        result: mpsc::Sender<Result<u64, SessionError>>,
    },
    TerminalVtResult {
        worker_id: String,
        worker_pid: u32,
        registration_nonce: String,
        attempt_id: u64,
        result: crate::TerminalVtCleanupResult,
        acknowledged: mpsc::Sender<Result<(), SessionError>>,
    },
    RecoveryAdmin {
        request: crate::RecoveryAdminRequest,
        result: mpsc::Sender<Result<crate::RecoveryAdminResponse, SessionError>>,
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
    admission: supervisor_loop::admission::RunningSeatReceipt,
    record: SupervisorSessionRecoveryRecord,
    child: Arc<Mutex<Child>>,
    supervisor_channel: UnixStream,
    #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    fixture_supervisor_transport: Option<worker_attempt::FixtureSupervisorTransportHandle>,
    #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    fixture_inherited_supervisor_control: bool,
    session: StartedSession,
    session_pid: u32,
    session_pgid: u32,
    worker_id: String,
    registration_nonce: String,
    control_path: PathBuf,
    _control_dir: TempDir,
    terminal_vt_reported_busy: bool,
}

struct PendingWorkerLifecycle {
    record: SupervisorSessionRecoveryRecord,
    child: Arc<Mutex<Child>>,
    release: PendingReleaseState,
    generation: u64,
    terminal_before_started: bool,
}

#[derive(Debug)]
enum PendingReleaseState {
    NotRequested,
    Requested { nonce: String },
    RecoveryRequired(crate::PayloadScopeRecoveryReason),
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

include!("contracts/guards.rs");
