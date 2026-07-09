use niralis_session_worker::run_worker_process;
use tracing_subscriber::EnvFilter;

fn main() {
    init_logging();

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    let exit_code = match run_worker_process(&mut stdin, &mut stdout) {
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
