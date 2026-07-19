use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(address) = args.next() else {
        std::process::exit(2);
    };
    let Some(name) = args.next() else {
        std::process::exit(2);
    };
    let Some(ready_path) = args.next() else {
        std::process::exit(2);
    };
    let connection = zbus::blocking::connection::Builder::address(address.as_str())
        .and_then(|builder| builder.name(name))
        .and_then(|builder| builder.build())
        .unwrap_or_else(|_| std::process::exit(3));
    let _connection = connection;
    let mut ready = UnixStream::connect(ready_path).unwrap_or_else(|_| std::process::exit(4));
    let _ = writeln!(ready, "ready");
    for line in io::stdin().lock().lines() {
        if matches!(line.as_deref(), Ok("exit")) {
            break;
        }
    }
}
