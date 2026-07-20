use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{LogindSessionId, SessionRequest, StartedSession, WorkerSecret};

/// Version 12 adds the post-ack payload-scope release rendezvous event.
pub const WORKER_PROTOCOL_VERSION: u32 = 12;
pub const MAX_WORKER_MESSAGE_BYTES: usize = 64 * 1024;
/// Version 4 adds authenticated worker terminal-VT intent/result reporting.
pub const WORKER_CONTROL_PROTOCOL_VERSION: u32 = 4;
pub const MAX_WORKER_CONTROL_MESSAGE_BYTES: usize = 4096;
/// Private inherited descriptor used for supervisor lifecycle traffic. Stdin
/// remains a one-shot WorkerRequest transport and is expected to reach EOF.
pub const WORKER_SUPERVISOR_FD_ENV: &str = "NIRALIS_WORKER_SUPERVISOR_FD";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerEnvelope<T> {
    pub version: u32,
    pub message: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionExecPlan {
    pub source_path: Vec<u8>,
    pub executable: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
}

impl SessionExecPlan {
    pub const MAX_ARGC: usize = 64;
    pub const MAX_ARG_BYTES: usize = 4096;
    pub const MAX_ARGV_BYTES: usize = 16 * 1024;

    pub fn validate(&self) -> Result<(), ()> {
        if self.source_path.is_empty()
            || self.source_path.len() > 4096
            || self.executable.is_empty()
            || self.executable.len() > 4096
            || self.source_path.contains(&0)
            || self.executable.contains(&0)
            || self.argv.is_empty()
            || self.argv.len() > Self::MAX_ARGC
            || self
                .argv
                .iter()
                .any(|arg| arg.is_empty() || arg.len() > Self::MAX_ARG_BYTES || arg.contains(&0))
            || self.argv.iter().map(|arg| arg.len() + 1).sum::<usize>() > Self::MAX_ARGV_BYTES
        {
            return Err(());
        }
        let executable = std::path::Path::new(std::ffi::OsStr::from_bytes(&self.executable));
        if !executable.is_absolute() {
            return Err(());
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerRequest {
    PrepareSession {
        request: SessionRequest,
    },
    PamSession {
        request: SessionRequest,
        launch_plan: SessionExecPlan,
        pam_service: String,
        password: WorkerSecret,
        session_child_path: PathBuf,
        session_probe_path: PathBuf,
        control_path: PathBuf,
        worker_id: String,
        launcher_pid: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerControlRequest {
    PayloadScopeRegistered {
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
    },
    PayloadScopeReleaseRequested {
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
        release_nonce: String,
        scope_identity: PayloadScopeIdentity,
        local_cleanup_succeeded: bool,
    },
    PayloadScopeReleased {
        worker_id: String,
        expected_worker_pid: u32,
        registration_nonce: String,
        release_nonce: String,
    },
    PayloadScopeRecoveryRequired {
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
    /// Non-terminal event proving that the worker entered the authenticated
    /// launch lifecycle. A3.1 will use the same stream for scope registration.
    Preparing {
        worker_id: String,
    },
    /// Reserved pre-Started lifecycle event. Production does not emit this
    /// until a real transient scope identity exists.
    PayloadScopePrepared {
        worker_id: String,
        expected_worker_pid: u32,
        session_pid: u32,
        registration_nonce: String,
        scope_identity: PayloadScopeIdentity,
    },
    /// Non-authoritative wakeup. The correlated release request is exchanged
    /// over the inherited, peer-validated supervisor channel.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadScopeRecoveryReason {
    VerificationUnavailable,
    UnitStillActive,
    MembershipNotEmpty,
    InvocationIdMismatch,
    IdentityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadScopeIdentity {
    pub unit_name: String,
    pub invocation_id: String,
    pub expected_uid: u32,
    pub logind_session_id: LogindSessionId,
}

impl PayloadScopeIdentity {
    pub fn validate(&self) -> bool {
        self.unit_name.starts_with("niralis-payload-")
            && self.unit_name.ends_with(".scope")
            && self.unit_name.len() <= 255
            && self
                .unit_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
            && self.invocation_id.len() == 32
            && self
                .invocation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && self.expected_uid != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerErrorCode {
    UnsupportedVersion,
    InvalidRequest,
    InternalError,
    RealGraphicalSessionNotAuthorized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerSessionFailureCode {
    PamIdentityUnavailable,
    IdentityResolutionFailed,
    SupplementaryGroupsResolutionFailed,
    OpenFailed,
    InternalPanic,
    SessionChildFailed,
    /// The worker inherited an existing logind session, preventing pam_systemd
    /// from creating the Niralis-owned session.
    WorkerAlreadyInLogindSession,
    LogindFailed,
    LogindSessionIdMismatch,
    RuntimeEnvironmentFailed,
    RuntimeDirectoryInvalid,
    LaunchSpecMissing,
    LaunchSpecMalformed,
    ExecutableUnavailable,
    ExecFailed,
    CommitFailed,
}
