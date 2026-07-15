use serde::{Deserialize, Serialize};

use crate::isolation::PostDropIsolationProof;
use crate::privilege_drop::{AppliedCredentials, PrivilegeDropTarget};
use crate::selinux::PamSelinuxExecContext;
use niralis_session::SessionExecPlan;

pub const SESSION_CHILD_PROTOCOL_VERSION: u32 = 9;
pub const SESSION_EXEC_PROBE_VERSION: u32 = 2;
pub const MAX_SESSION_CHILD_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildUnixCredentials {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildCredentialProof {
    pub real_uid: u32,
    pub effective_uid: u32,
    pub saved_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub saved_gid: u32,
    pub supplementary_gids: Vec<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildUnixPath {
    pub bytes: Vec<u8>,
}

impl SessionChildUnixPath {
    pub fn new(path: &std::path::Path) -> Result<Self, &'static str> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes().to_vec();
        if bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0) {
            return Err("invalid unix path");
        }
        Ok(Self { bytes })
    }
    pub fn to_path_buf(&self) -> Result<std::path::PathBuf, &'static str> {
        use std::os::unix::ffi::OsStringExt;
        if self.bytes.is_empty() || self.bytes.len() > 4096 || self.bytes.contains(&0) {
            return Err("invalid unix path");
        }
        Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(
            self.bytes.clone(),
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildRuntimeContext {
    pub home: SessionChildUnixPath,
    pub shell: SessionChildUnixPath,
    pub session_type: String,
    #[serde(default)]
    pub session_class: String,
    #[serde(default)]
    pub session_desktop: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub runtime_dir: SessionChildUnixPath,
    #[serde(default)]
    pub seat: String,
    #[serde(default)]
    pub vtnr: u32,
    #[serde(default)]
    pub dbus_session_bus_address: Option<String>,
    #[serde(default)]
    pub imported_locale: Vec<(String, String)>,
    /// Present only when pam_selinux prepared a context for this session.
    pub selinux_exec_context: Option<PamSelinuxExecContext>,
    pub probe_path: SessionChildUnixPath,
    pub exec_plan: SessionExecPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildTerminalContext {
    pub seat: String,
    pub vtnr: u32,
    pub fd: i32,
    pub device_major: u32,
    pub device_minor: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChildTerminalProof {
    pub seat: String,
    pub vtnr: u32,
    pub fd: i32,
    pub device_major: u32,
    pub device_minor: u32,
    pub controlling_sid: u32,
    pub foreground_pgid: u32,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProcessIdentityProof {
    pub pid: u32,
    pub sid: u32,
    pub pgid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRuntimeEnvironmentProof {
    pub home: SessionChildUnixPath,
    pub user: String,
    pub logname: String,
    pub shell: SessionChildUnixPath,
    pub path: String,
    pub session_type: String,
    #[serde(default)]
    pub session_class: String,
    #[serde(default)]
    pub session_desktop: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub runtime_dir: SessionChildUnixPath,
    #[serde(default)]
    pub seat: String,
    #[serde(default)]
    pub vtnr: u32,
    #[serde(default)]
    pub dbus_session_bus_address: Option<String>,
    #[serde(default)]
    pub imported_locale: Vec<(String, String)>,
    #[serde(default)]
    pub forbidden_variables_present: Vec<String>,
    #[serde(default)]
    pub user_bus_connected: bool,
    pub cwd: SessionChildUnixPath,
    pub exec_plan: SessionExecPlan,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionChildCommit {
    Exec,
    Abort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalExecFailure {
    pub stage: String,
    pub errno: i32,
}

/// Private, post-drop handoff from the session child to the trusted exec probe.
/// This never crosses the worker/child JSON protocol: it is serialized into a
/// sealed anonymous file descriptor immediately before execing the probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProbeHandoff {
    pub exec_plan: SessionExecPlan,
    pub selinux_exec_context: Option<PamSelinuxExecContext>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionChildRequest {
    ApplyCredentials {
        canonical_username: String,
        session_id: String,
        credentials: SessionChildUnixCredentials,
        runtime: SessionChildRuntimeContext,
        #[serde(default)]
        terminal: Option<SessionChildTerminalContext>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionChildResponse {
    Ready {
        canonical_username: String,
        session_id: String,
        child_pid: u32,
        applied_credentials: SessionChildUnixCredentials,
        credential_proof: SessionChildCredentialProof,
        isolation_proof: SessionChildIsolationProof,
        process_identity: SessionProcessIdentityProof,
        runtime_environment: SessionRuntimeEnvironmentProof,
        exec_probe_version: u32,
        #[serde(default)]
        terminal_proof: Option<SessionChildTerminalProof>,
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
    InvalidRuntimeContext,
    HomeDirectoryUnavailable,
    SessionBoundaryFailed,
    TerminalProofFailed,
    ExecFailed,
    RuntimeProbeFailed,
    CommitTimeout,
    CommitRejected,
    FinalExecFailed,
    InternalError,
}
