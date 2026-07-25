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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
