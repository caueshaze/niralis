#[cfg(test)]
mod graceful_coordinator_tests {
    include!("graceful_tests/support_lifecycle.rs");
    include!("graceful_tests/support_events.rs");
    include!("graceful_tests/termination_triggers.rs");
    include!("graceful_tests/finalization.rs");
    include!("graceful_tests/release_failures.rs");
}
