mod identity;
mod isolation;
mod privilege_drop;
mod runtime;
#[cfg(test)]
mod runtime_tests;
mod session_child;

pub use identity::{
    GroupResolutionError, IdentityError, NssSupplementaryGroupsResolver, NssUnixIdentityResolver,
    ResolvedUnixCredentials, SupplementaryGroupsResolver, UnixIdentity, UnixIdentityResolver,
};
pub use isolation::{
    validate_isolation_proof, CapabilityState, FdSanitizationError, InheritedFdSanitizer,
    IsolationPolicyError, LinuxInheritedFdSanitizer, LinuxPostDropAuditor, PostDropAuditError,
    PostDropAuditor, PostDropIsolationProof,
};
pub use privilege_drop::{
    AppliedCredentials, LibcPrivilegeDropper, PrivilegeDropError, PrivilegeDropTarget,
    PrivilegeDropper,
};
pub use runtime::{run_worker_process, WorkerAuthenticatorFactory};
pub use session_child::{
    ProcessSessionChildRunner, ProcessSessionChildRunnerFactory, SessionChildEnvelope,
    SessionChildError, SessionChildErrorCode, SessionChildExpectation, SessionChildIsolationProof,
    SessionChildReport, SessionChildResponse, SessionChildRunner, SessionChildRunnerFactory,
    SessionChildRuntimeContext, SessionChildUnixCredentials, SessionChildUnixPath,
    SessionProcessIdentityProof, SessionRuntimeEnvironmentProof, SESSION_CHILD_PROTOCOL_VERSION,
    SESSION_EXEC_PROBE_VERSION,
};

pub fn run_session_child() -> i32 {
    session_child::run_child_process()
}
