mod identity;
mod isolation;
mod logind;
mod payload_scope;
mod privilege_drop;
mod runtime;
#[cfg(test)]
mod runtime_tests;
mod selinux;
mod session_child;
mod smoke;
mod user_bus;
mod vt;

pub use identity::{
    GroupResolutionError, IdentityError, NssSupplementaryGroupsResolver, NssUnixIdentityResolver,
    ResolvedUnixCredentials, SupplementaryGroupsResolver, UnixIdentity, UnixIdentityResolver,
};
pub use isolation::{
    validate_isolation_proof, CapabilityState, FdSanitizationError, InheritedFdSanitizer,
    IsolationPolicyError, LinuxInheritedFdSanitizer, LinuxPostDropAuditor, PostDropAuditError,
    PostDropAuditor, PostDropCapabilitySanitizationError, PostDropIsolationProof,
};
pub use logind::{
    LogindError, LogindSessionId, LogindSessionIdentity, LogindSessionResolver, SdLoginResolver,
};
pub use payload_scope::{
    AuthoritativePayloadScope, PayloadScopeError, PayloadScopeManager, SystemdPayloadScopeManager,
};
pub use privilege_drop::{
    AppliedCredentials, LibcPrivilegeDropper, PrivilegeDropError, PrivilegeDropTarget,
    PrivilegeDropper,
};
pub use runtime::{
    run_worker_process, LinuxRuntimeDirValidator, RuntimeDirValidationError, RuntimeDirValidator,
    StubRuntimeDirValidator, WorkerAuthenticatorFactory,
};
pub use selinux::{
    LinuxSelinuxContextManager, PamSelinuxExecContext, SelinuxContextManager, SelinuxError,
};
pub use session_child::{
    FinalExecFailure, PendingExecHandoff, ProcessSessionChildRunner,
    ProcessSessionChildRunnerFactory, SessionChildCommit, SessionChildCredentialProof,
    SessionChildEnvelope, SessionChildError, SessionChildErrorCode, SessionChildExpectation,
    SessionChildIsolationProof, SessionChildReport, SessionChildResponse, SessionChildRunner,
    SessionChildRunnerFactory, SessionChildRuntimeContext, SessionChildTerminalContext,
    SessionChildTerminalProof, SessionChildUnixCredentials, SessionChildUnixPath,
    SessionProbeHandoff, SessionProcessIdentityProof, SessionRuntimeEnvironmentProof,
    SESSION_CHILD_PROTOCOL_VERSION, SESSION_EXEC_PROBE_VERSION,
};
pub use smoke::{authorize_real_graphical_smoke, RealGraphicalSmokeGuardError};
pub use user_bus::{prove_user_bus, UserBusError};
pub use vt::{
    LinuxVirtualTerminalAllocator, OwnedVirtualTerminal, VirtualTerminalAllocator,
    VirtualTerminalError, VirtualTerminalGuard, VirtualTerminalLease,
};

pub fn run_session_child() -> i32 {
    session_child::run_child_process()
}
