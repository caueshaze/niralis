use std::io::Read;
use std::thread;
use std::time::Duration;

fn main() {
    let mut stdin = std::io::stdin().lock();
    let _ = stdin.read_to_end(&mut Vec::new());
    thread::sleep(Duration::from_secs(5));
}
