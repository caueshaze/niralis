use serde::{Deserialize, Serialize};

use crate::isolation::PostDropIsolationProof;
use crate::privilege_drop::{AppliedCredentials, PrivilegeDropTarget};

pub const SESSION_CHILD_PROTOCOL_VERSION: u32 = 3;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildIsolationProof {
    pub effective_capabilities: Vec<u32>,
    pub permitted_capabilities: Vec<u32>,
    pub inheritable_capabilities: Vec<u32>,
    pub ambient_capabilities: Vec<u32>,
    pub bounding_capabilities: Vec<u32>,
    pub cap_last_cap: u32,
    pub securebits: u32,
    pub no_new_privs: bool,
    pub open_fds: Vec<i32>,
}

impl From<&PostDropIsolationProof> for SessionChildIsolationProof {
    fn from(proof: &PostDropIsolationProof) -> Self {
        Self {
            effective_capabilities: proof.capabilities.effective.clone(),
            permitted_capabilities: proof.capabilities.permitted.clone(),
            inheritable_capabilities: proof.capabilities.inheritable.clone(),
            ambient_capabilities: proof.capabilities.ambient.clone(),
            bounding_capabilities: proof.capabilities.bounding.clone(),
            cap_last_cap: proof.capabilities.cap_last_cap,
            securebits: proof.securebits,
            no_new_privs: proof.no_new_privs,
            open_fds: proof.open_fds.clone(),
        }
    }
}

impl From<SessionChildIsolationProof> for PostDropIsolationProof {
    fn from(proof: SessionChildIsolationProof) -> Self {
        Self {
            capabilities: crate::isolation::CapabilityState {
                effective: proof.effective_capabilities,
                permitted: proof.permitted_capabilities,
                inheritable: proof.inheritable_capabilities,
                ambient: proof.ambient_capabilities,
                bounding: proof.bounding_capabilities,
                cap_last_cap: proof.cap_last_cap,
            },
            securebits: proof.securebits,
            no_new_privs: proof.no_new_privs,
            open_fds: proof.open_fds,
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
        isolation_proof: SessionChildIsolationProof,
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
    FdSanitizationFailed,
    IsolationAuditFailed,
    IsolationPolicyFailed,
    InternalError,
}
