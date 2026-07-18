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
    #[cfg(any(feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    fixture_recovery_provider: Option<Arc<SupervisorFixtureRecoveryProvider>>,
}

#[derive(Debug)]
enum WorkerSupervisorMessage {
    ReserveSeat {
        worker_id: String,
        result: mpsc::Sender<Result<PreviousVtIdentity, SessionError>>,
    },
    CancelSeatReservation {
        worker_id: String,
    },
    BeginPending {
        worker_id: String,
        worker_pid: u32,
        launcher_pid: u32,
        session: StartedSession,
        child: Arc<Mutex<Child>>,
        previous_vt: PreviousVtIdentity,
        result: mpsc::Sender<Result<(), SessionError>>,
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
        worker_id: String,
        expected_clean: bool,
        worker_exit_status: Option<ExitStatus>,
        result: mpsc::Sender<Result<(), SessionError>>,
    },
    Register {
        runtime_id: RuntimeSessionId,
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
    record: SupervisorSessionRecoveryRecord,
    child: Arc<Mutex<Child>>,
    _supervisor_channel: UnixStream,
    session: StartedSession,
    session_pid: u32,
    session_pgid: u32,
    worker_id: String,
    control_path: PathBuf,
    _control_dir: TempDir,
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

struct PendingSupervisorGuard {
    supervisor: Arc<WorkerSupervisor>,
    worker_id: String,
    expected_clean: bool,
    worker_exit_status: Option<ExitStatus>,
}

struct SeatReservationGuard {
    supervisor: Arc<WorkerSupervisor>,
    worker_id: String,
    armed: bool,
}

impl SeatReservationGuard {
    fn consume(&mut self) {
        self.armed = false;
    }
}

impl Drop for SeatReservationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.supervisor.cancel_seat_reservation(&self.worker_id);
        }
    }
}

impl Drop for PendingSupervisorGuard {
    fn drop(&mut self) {
        if !self.worker_id.is_empty() {
            let _ = self
                .supervisor
                .abort_pending(
                    &self.worker_id,
                    self.expected_clean,
                    self.worker_exit_status,
                );
        }
    }
}

impl PendingSupervisorGuard {
    fn mark_expected_clean(&mut self, status: ExitStatus) {
        self.expected_clean = true;
        self.worker_exit_status = Some(status);
    }

    fn complete(mut self) -> Result<(), SessionError> {
        let result = self
            .supervisor
            .abort_pending(
                &self.worker_id,
                self.expected_clean,
                self.worker_exit_status,
            );
        self.worker_id.clear();
        result
    }
}
