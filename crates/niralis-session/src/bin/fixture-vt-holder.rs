use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;

use serde::Serialize;

#[derive(Serialize)]
struct Ready {
    kind: &'static str,
    pid: u32,
    starttime: u64,
    uid: u32,
    fd: i32,
    executable_device: u64,
    executable_inode: u64,
    device_major: u32,
    device_minor: u32,
    cgroup: Option<String>,
}

#[derive(Serialize)]
struct Closed {
    kind: &'static str,
}

fn main() {
    let (target_vt, ready_socket, release_fd) = parse();
    let path = format!("/dev/tty{target_vt}");
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .open(&path)
        .unwrap_or_else(|_| std::process::exit(3));
    let metadata = tty.metadata().unwrap_or_else(|_| std::process::exit(4));
    if !metadata.file_type().is_char_device() {
        std::process::exit(5);
    }
    let executable = fs::metadata("/proc/self/exe").unwrap_or_else(|_| std::process::exit(6));
    let message = Ready {
        kind: "Ready",
        pid: std::process::id(),
        starttime: starttime().unwrap_or_else(|| std::process::exit(7)),
        uid: unsafe { libc::geteuid() },
        fd: tty.as_raw_fd(),
        executable_device: executable.dev(),
        executable_inode: executable.ino(),
        device_major: libc::major(metadata.rdev()),
        device_minor: libc::minor(metadata.rdev()),
        cgroup: fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|value| {
                value
                    .lines()
                    .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
            }),
    };
    let mut ready = UnixStream::connect(ready_socket).unwrap_or_else(|_| std::process::exit(8));
    write_message(&mut ready, &message);
    let release = unsafe { OwnedFd::from_raw_fd(release_fd) };
    let mut pollfd = libc::pollfd {
        fd: release.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pollfd, 1, -1) } != 1 || pollfd.revents & libc::POLLIN == 0 {
        std::process::exit(9);
    }
    drop(tty);
    write_message(&mut ready, &Closed { kind: "Closed" });
}

fn write_message<T: Serialize>(stream: &mut UnixStream, message: &T) {
    let bytes = serde_json::to_vec(message).unwrap_or_else(|_| std::process::exit(10));
    if bytes.len() > 1024 || stream.write_all(&bytes).is_err() || stream.write_all(b"\n").is_err() {
        std::process::exit(11);
    }
}

fn starttime() -> Option<u64> {
    fs::read_to_string("/proc/self/stat")
        .ok()?
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn parse() -> (u32, String, i32) {
    let mut arguments = std::env::args().skip(1);
    let mut target = None;
    let mut socket = None;
    let mut release = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--target-vt" if target.is_none() => {
                target = arguments.next().and_then(|value| value.parse().ok())
            }
            "--ready-socket" if socket.is_none() => socket = arguments.next(),
            "--release-eventfd" if release.is_none() => {
                release = arguments.next().and_then(|value| value.parse().ok())
            }
            _ => std::process::exit(2),
        }
    }
    match (
        target.filter(|value| *value > 0),
        socket.filter(|value| !value.is_empty()),
        release.filter(|value| *value >= 0),
    ) {
        (Some(target), Some(socket), Some(release)) => (target, socket, release),
        _ => std::process::exit(2),
    }
}
