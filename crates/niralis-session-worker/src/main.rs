use tracing_subscriber::EnvFilter;

fn main() {
    let signals = match niralis_session_worker::WorkerSignalFd::install() {
        Ok(signals) => signals,
        Err(_) => std::process::exit(1),
    };
    init_logging();

    let supervisor = niralis_session_worker::take_inherited_supervisor_channel().ok();

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    let exit_code = match niralis_session_worker::run_worker_process_with_signals(
        &mut stdin,
        &mut stdout,
        &signals,
        supervisor
            .as_ref()
            .map_or(-1, std::os::fd::AsRawFd::as_raw_fd),
    ) {
        Ok(()) => 0,
        Err(_) => 1,
    };

    std::process::exit(exit_code);
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
