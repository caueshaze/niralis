mod precommit_runtime;
mod recovery;
mod recovery_admin_host;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
use crate::worker_attempt;
use precommit_runtime::*;
#[cfg(any(
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub use recovery::SupervisorFixtureBoundaryMode;
#[cfg(feature = "supervisor-test-fixtures")]
pub use recovery::SupervisorFixtureSnapshot;
use recovery::*;
#[cfg(feature = "supervisor-test-fixtures")]
pub use recovery::{
    PhysicalPreviousBootSmoke, PhysicalPreviousBootSmokeFailpoint, PhysicalPreviousBootSmokePaths,
};
#[cfg(feature = "supervisor-test-fixtures")]
use std::os::fd::AsRawFd;
include!("launcher/contracts.rs");
mod login_transaction;
mod supervisor_loop;
#[cfg(test)]
use supervisor_loop::support::finalize_clean_worker_exit;
use supervisor_loop::support::kill_shared_worker;
include!("launcher/supervisor_api.rs");
include!("launcher/supervisor_shutdown.rs");
include!("launcher/public_api.rs");
include!("launcher/recovery_admin_api.rs");
#[cfg(feature = "supervisor-test-fixtures")]
include!("launcher/public_api_fixtures.rs");
include!("launcher/pam_prompt.rs");
include!("launcher/launch_protocol.rs");
include!("launcher/launch_completion.rs");
include!("launcher/interface_tests_helpers.rs");
