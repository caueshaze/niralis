use serde::{Deserialize, Serialize};

pub const SESSION_CHILD_PROTOCOL_VERSION: u32 = 1;
pub const MAX_SESSION_CHILD_MESSAGE_BYTES: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildEnvelope<T> {
    pub version: u32,
    pub message: T,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionChildRequest {
    Probe {
        canonical_username: String,
        session_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionChildResponse {
    Ready {
        canonical_username: String,
        session_id: String,
        child_pid: u32,
    },
    Rejected {
        code: SessionChildErrorCode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionChildErrorCode {
    UnsupportedVersion,
    InvalidRequest,
    InternalError,
}
