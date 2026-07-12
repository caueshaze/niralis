use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{LogindSessionId, SessionRequest, StartedSession, WorkerSecret};

pub const WORKER_PROTOCOL_VERSION: u32 = 9;
pub const MAX_WORKER_MESSAGE_BYTES: usize = 64 * 1024;
pub const WORKER_CONTROL_PROTOCOL_VERSION: u32 = 1;
pub const MAX_WORKER_CONTROL_MESSAGE_BYTES: usize = 4096;

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
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerControlRequest {
    Terminate {
        worker_id: String,
        expected_worker_pid: u32,
        expected_session_pid: u32,
        expected_session_pgid: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerResponse {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerErrorCode {
    UnsupportedVersion,
    InvalidRequest,
    InternalError,
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
