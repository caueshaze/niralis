#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerPamSessionRequest {
    pub request: SessionRequest,
    pub connection: Option<crate::LoginRequestBinding>,
    pub launch_plan: Box<SessionExecPlan>,
    pub pam_service: String,
    pub password: WorkerSecret,
    pub session_child_path: Box<PathBuf>,
    pub session_probe_path: Box<PathBuf>,
    pub control_path: Box<PathBuf>,
    pub worker_id: String,
    pub launcher_pid: u32,
    pub transaction: Box<WorkerTransactionIdentity>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerRequest {
    PrepareSession { request: SessionRequest },
    PamSession(WorkerPamSessionRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerControlRequest {
    Authenticate {
        transaction: ControlTransactionIdentity,
        worker_id: String,
        expected_worker_pid: u32,
        secret: WorkerSecret,
    },
    PayloadScopeRegistered {
        transaction: ControlTransactionIdentity,
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
    },
    PayloadScopeReleaseRequested {
        transaction: ControlTransactionIdentity,
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
        release_nonce: String,
        scope_identity: PayloadScopeIdentity,
        local_cleanup_succeeded: bool,
    },
    PayloadScopeReleased {
        transaction: ControlTransactionIdentity,
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
        release_nonce: String,
    },
    PayloadScopeRecoveryRequired {
        transaction: ControlTransactionIdentity,
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
        release_nonce: String,
        reason: PayloadScopeRecoveryReason,
    },
    Terminate {
        worker_id: String,
        expected_worker_pid: u32,
        expected_session_pid: u32,
        expected_session_pgid: u32,
    },
    TerminalVtCleanupIntent {
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
        scope_identity: PayloadScopeIdentity,
    },
    TerminalVtCleanupIntentAcknowledged {
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
        attempt_id: u64,
    },
    TerminalVtCleanupResult {
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
        attempt_id: u64,
        result: TerminalVtCleanupResult,
    },
    TerminalVtCleanupResultAcknowledged {
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
        attempt_id: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalVtCleanupResult {
    Released,
    VtDisallocateBusy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerResponse {
    Preparing {
        worker_id: String,
        transaction: WorkerTransactionIdentity,
    },
    PayloadScopePrepared {
        worker_id: String,
        transaction: WorkerTransactionIdentity,
        expected_worker_pid: u32,
        session_pid: u32,
        registration_nonce: String,
        scope_identity: PayloadScopeIdentity,
    },
    PayloadScopeReleaseReady {
        worker_id: String,
    },
    Started {
        session: StartedSession,
        session_pid: u32,
        session_pgid: u32,
        fixture_version: u32,
        worker_id: String,
        logind_session_id: LogindSessionId,
        transaction: WorkerTransactionIdentity,
    },
    Ready {
        session: StartedSession,
    },
    AuthenticationFailed,
    SessionFailed {
        code: WorkerSessionFailureCode,
    },
    Rejected {
        code: WorkerErrorCode,
    },
}
