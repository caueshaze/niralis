use serde::{Deserialize, Serialize};

use crate::privilege_drop::{AppliedCredentials, PrivilegeDropTarget};

pub const SESSION_CHILD_PROTOCOL_VERSION: u32 = 2;
pub const MAX_SESSION_CHILD_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildUnixCredentials {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
}

impl From<&PrivilegeDropTarget> for SessionChildUnixCredentials {
    fn from(target: &PrivilegeDropTarget) -> Self {
        Self {
            uid: target.uid,
            gid: target.gid,
            supplementary_gids: target.supplementary_gids.clone(),
        }
    }
}

impl From<&AppliedCredentials> for SessionChildUnixCredentials {
    fn from(applied: &AppliedCredentials) -> Self {
        Self {
            uid: applied.uid,
            gid: applied.gid,
            supplementary_gids: applied.supplementary_gids.clone(),
        }
    }
}

impl From<SessionChildUnixCredentials> for PrivilegeDropTarget {
    fn from(credentials: SessionChildUnixCredentials) -> Self {
        Self {
            uid: credentials.uid,
            gid: credentials.gid,
            supplementary_gids: credentials.supplementary_gids,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildEnvelope<T> {
    pub version: u32,
    pub message: T,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionChildRequest {
    ApplyCredentials {
        canonical_username: String,
        session_id: String,
        credentials: SessionChildUnixCredentials,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionChildResponse {
    Ready {
        canonical_username: String,
        session_id: String,
        child_pid: u32,
        applied_credentials: SessionChildUnixCredentials,
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
    RootUidDisallowed,
    PrivilegeDropFailed,
    CredentialMismatch,
    InternalError,
}
