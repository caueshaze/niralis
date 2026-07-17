fn main() {
    let mode = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("NIRALIS_FULL_WORKER_FIXTURE_MODE").ok())
        .unwrap_or_else(|| "cooperative".into());
    let signals = niralis_session_worker::WorkerSignalFd::install().unwrap_or_else(|_| {
        std::process::exit(70);
    });
    let supervisor = niralis_session_worker::take_inherited_supervisor_channel()
        .unwrap_or_else(|_| std::process::exit(70));
    let harness_fd = std::env::var("NIRALIS_FULL_WORKER_HARNESS_FD")
        .ok()
        .and_then(|value| value.parse().ok());
    if niralis_session_worker::run_full_worker_fixture(
        &mode,
        harness_fd,
        std::os::fd::AsRawFd::as_raw_fd(&supervisor),
        &signals,
    )
    .is_err()
    {
        std::process::exit(1);
    }
}
