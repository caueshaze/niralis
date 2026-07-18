mod error;
mod launcher;
mod mock;
mod protocol;
mod scope_release;
mod secret;
#[cfg(test)]
mod tests;
mod types;
mod worker_attempt;
mod worker_io;

pub use error::SessionError;
#[cfg(any(
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub use launcher::SupervisorFixtureBoundaryMode;
#[cfg(feature = "supervisor-test-fixtures")]
pub use launcher::SupervisorFixtureSnapshot;
pub use launcher::WorkerSessionLauncher;
pub use mock::MockSessionLauncher;
pub use protocol::{
    PayloadScopeIdentity, PayloadScopeRecoveryReason, SessionExecPlan, WorkerControlRequest,
    WorkerEnvelope, WorkerErrorCode, WorkerRequest, WorkerResponse, WorkerSessionFailureCode,
    MAX_WORKER_CONTROL_MESSAGE_BYTES, MAX_WORKER_MESSAGE_BYTES, WORKER_CONTROL_PROTOCOL_VERSION,
    WORKER_PROTOCOL_VERSION, WORKER_SUPERVISOR_FD_ENV,
};
pub use scope_release::{
    PayloadScopeReleaseVerifier, ScopeReleaseVerification, SystemdPayloadScopeReleaseVerifier,
};
pub use secret::WorkerSecret;
#[cfg(any(test, feature = "integration-test-control"))]
pub use types::RuntimeSessionId;
pub use types::{LogindSessionId, SessionLauncher, SessionRequest, StartedSession};
pub use worker_io::{read_control_request, read_envelope, write_control_request, write_envelope};
