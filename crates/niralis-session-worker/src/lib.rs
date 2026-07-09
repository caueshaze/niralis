mod identity;
mod privilege_drop;
mod runtime;
#[cfg(test)]
mod runtime_tests;
mod session_child;

pub use identity::{
    GroupResolutionError, IdentityError, NssSupplementaryGroupsResolver, NssUnixIdentityResolver,
    ResolvedUnixCredentials, SupplementaryGroupsResolver, UnixIdentity, UnixIdentityResolver,
};
pub use privilege_drop::{
    AppliedCredentials, LibcPrivilegeDropper, PrivilegeDropError, PrivilegeDropTarget,
    PrivilegeDropper,
};
pub use runtime::{run_worker_process, WorkerAuthenticatorFactory};
pub use session_child::{
    ProcessSessionChildRunner, ProcessSessionChildRunnerFactory, SessionChildError,
    SessionChildExpectation, SessionChildReport, SessionChildRunner, SessionChildRunnerFactory,
};

pub fn run_session_child() -> i32 {
    session_child::run_child_process()
}
