use serde::{Deserialize, Serialize};

use crate::{SessionRequest, StartedSession, WorkerSecret};

pub const WORKER_PROTOCOL_VERSION: u32 = 2;
pub const MAX_WORKER_MESSAGE_BYTES: usize = 64 * 1024;

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
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerResponse {
    Ready { session: StartedSession },
    AuthenticationFailed,
    SessionFailed { code: WorkerSessionFailureCode },
    Rejected { code: WorkerErrorCode },
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
    IdentityResolutionFailed,
    OpenFailed,
    InternalPanic,
}
