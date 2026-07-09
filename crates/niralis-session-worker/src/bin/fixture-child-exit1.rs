fn main() {
    let code = niralis_session_worker::run_session_child();
    std::process::exit(if code == 0 { 1 } else { code });
}
