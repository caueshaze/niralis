use std::thread;
use std::time::Duration;

fn main() {
    if niralis_session_worker::run_session_child() == 0 {
        thread::sleep(Duration::from_secs(5));
    }
}
