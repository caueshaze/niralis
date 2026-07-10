use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{LogindSessionId, SessionRequest, StartedSession, WorkerSecret};

pub const WORKER_PROTOCOL_VERSION: u32 = 8;
pub const MAX_WORKER_MESSAGE_BYTES: usize = 64 * 1024;
pub const WORKER_CONTROL_PROTOCOL_VERSION: u32 = 1;
pub const MAX_WORKER_CONTROL_MESSAGE_BYTES: usize = 4096;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerEnvelope<T> {
    pub version: u32,
    pub message: T,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerRequest {
    PrepareSession {
        request: SessionRequest,
    },
    PamSession {
        request: SessionRequest,
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
    LogindFailed,
    LogindSessionIdMismatch,
    RuntimeEnvironmentFailed,
    RuntimeDirectoryInvalid,
}
