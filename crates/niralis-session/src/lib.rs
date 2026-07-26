mod error;
mod launcher;
mod mock;
mod protocol;
mod recovery_admin;
mod scope_release;
mod secret;
#[cfg(test)]
mod tests;
mod types;
mod worker_attempt;
mod worker_io;

pub use error::SessionError;
#[cfg(feature = "supervisor-test-fixtures")]
pub use launcher::PersistentSupervisorFixtureOptions;
#[cfg(any(
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub use launcher::SupervisorFixtureBoundaryMode;
#[cfg(feature = "supervisor-test-fixtures")]
pub use launcher::SupervisorFixtureSnapshot;
pub use launcher::WorkerSessionLauncher;
#[cfg(feature = "supervisor-test-fixtures")]
pub use launcher::{
    PhysicalPreviousBootSmoke, PhysicalPreviousBootSmokeFailpoint, PhysicalPreviousBootSmokePaths,
};
pub use mock::MockSessionLauncher;
pub use protocol::{
    ControlTransactionIdentity, PayloadScopeIdentity, PayloadScopeRecoveryReason, SessionExecPlan,
    SessionExecPlanValidationError, TerminalVtCleanupResult, WorkerControlRequest, WorkerEnvelope,
    WorkerErrorCode, WorkerPamSessionRequest, WorkerRequest, WorkerResponse,
    WorkerSessionFailureCode, WorkerTransactionIdentity, FIXTURE_SUPERVISOR_READ_FD_ENV,
    FIXTURE_SUPERVISOR_TRANSPORT_ENV, FIXTURE_SUPERVISOR_WRITE_FD_ENV,
    MAX_WORKER_CONTROL_MESSAGE_BYTES, MAX_WORKER_MESSAGE_BYTES, WORKER_CONTROL_PROTOCOL_VERSION,
    WORKER_PROTOCOL_VERSION, WORKER_SUPERVISOR_FD_ENV,
};
pub use recovery_admin::*;
pub use scope_release::{
    PayloadScopeReleaseVerifier, ScopeReleaseVerification, SystemdPayloadScopeReleaseVerifier,
};
pub use secret::{LoginSecret, WorkerSecret};
#[cfg(any(test, feature = "integration-test-control"))]
pub use types::RuntimeSessionId;
pub use types::{
    LoginBackendFactory, LoginStartError, LoginStartOutcome, LogindSessionId, SessionLauncher,
    SessionRequest, StartedSession, UnauthenticatedLoginRequest, UnboundLoginBackend,
};
pub use worker_io::{read_control_request, read_envelope, write_control_request, write_envelope};
