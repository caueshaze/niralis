use tracing_subscriber::EnvFilter;

fn main() {
    let mode = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("NIRALIS_FULL_WORKER_FIXTURE_MODE").ok())
        .unwrap_or_else(|| "cooperative".into());
    let signals = niralis_session_worker::WorkerSignalFd::install().unwrap_or_else(|_| {
        eprintln!("fixture-full-worker failure stage=install-signals");
        std::process::exit(70);
    });
    init_logging();
    let supervisor = niralis_session_worker::take_inherited_supervisor_channel_for_test()
        .unwrap_or_else(|error| {
            eprintln!("fixture-full-worker failure stage=inherited-supervisor cause={error:?}");
            std::process::exit(70);
        });
    let harness_fd = std::env::var("NIRALIS_FULL_WORKER_HARNESS_FD")
        .ok()
        .and_then(|value| value.parse().ok());
    if let Err(error) = niralis_session_worker::run_full_worker_fixture(
        &mode,
        harness_fd,
        std::os::fd::AsRawFd::as_raw_fd(&supervisor),
        &signals,
    ) {
        eprintln!("fixture-full-worker failure stage=runtime cause={error:?}");
        std::process::exit(1);
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
