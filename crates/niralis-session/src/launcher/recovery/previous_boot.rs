#[cfg(test)]
#[path = "previous_boot_category_tests.rs"]
mod category_tests;
#[cfg(any(test, feature = "supervisor-test-fixtures"))]
#[path = "previous_boot_fixtures.rs"]
mod fixtures;
#[path = "previous_boot_planner.rs"]
mod planner;
#[cfg(test)]
#[path = "previous_boot_tests.rs"]
mod tests;
#[path = "previous_boot_types.rs"]
mod types;

pub(crate) use planner::*;
pub(crate) use types::*;

#[cfg(feature = "supervisor-test-fixtures")]
const _: fn() = fixtures::controlled_previous_boot_host_for_fixture_linkage;
#[cfg(test)]
pub(crate) use fixtures::ControlledPreviousBootInspectionHost;
