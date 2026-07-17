#[cfg(test)]
mod tests {
    include!("tests/support.rs");
    include!("tests/scripted_provider.rs");
    include!("tests/precommit.rs");
    include!("tests/pinning.rs");
    include!("tests/termination.rs");
    include!("tests/empty_boundary.rs");
    include!("tests/backend_failures.rs");
    include!("tests/validation.rs");
}
