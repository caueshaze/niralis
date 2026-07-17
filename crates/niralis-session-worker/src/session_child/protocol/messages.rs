
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
