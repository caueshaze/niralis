fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "cooperative".into());
    let signals = niralis_session_worker::WorkerSignalFd::install().unwrap_or_else(|_| {
        std::process::exit(70);
    });
    if niralis_session_worker::run_full_worker_fixture(&mode, 3, &signals).is_err() {
        std::process::exit(1);
    }
}
