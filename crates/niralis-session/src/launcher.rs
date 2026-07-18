mod recovery;
#[cfg(any(
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub use recovery::SupervisorFixtureBoundaryMode;
#[cfg(feature = "supervisor-test-fixtures")]
pub use recovery::SupervisorFixtureSnapshot;
use recovery::*;
#[cfg(any(
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
use std::os::fd::AsRawFd;
include!("launcher/contracts.rs");
mod supervisor_loop;
#[cfg(test)]
use supervisor_loop::support::finalize_clean_worker_exit;
use supervisor_loop::support::kill_shared_worker;
include!("launcher/supervisor_api.rs");
include!("launcher/supervisor_shutdown.rs");
include!("launcher/public_api.rs");
include!("launcher/launch_protocol.rs");
include!("launcher/launch_completion.rs");
include!("launcher/interface_tests_helpers.rs");
