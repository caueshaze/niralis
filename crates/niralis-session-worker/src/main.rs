use tracing_subscriber::EnvFilter;

fn main() {
    let signals = match niralis_session_worker::WorkerSignalFd::install() {
        Ok(signals) => signals,
        Err(_) => std::process::exit(1),
    };
    init_logging();

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    let exit_code = match niralis_session_worker::run_worker_process_with_signals(
        &mut stdin,
        &mut stdout,
        &signals,
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
