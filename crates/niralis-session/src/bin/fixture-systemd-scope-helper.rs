use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

fn main() {
    let (ready_socket, spawn_descendant) = parse_fixture_arguments();
    let descendant = if spawn_descendant {
        match unsafe { libc::fork() } {
            0 => loop {
                unsafe { libc::pause() };
            },
            pid if pid > 0 => Some(pid as u32),
            _ => std::process::exit(3),
        }
    } else {
        None
    };
    let mut ready = UnixStream::connect(ready_socket).unwrap_or_else(|_| std::process::exit(4));
    if writeln!(
        ready,
        "READY helper_pid={} descendant_pid={}",
        std::process::id(),
        descendant.map_or(0, |pid| pid)
    )
    .is_err()
    {
        std::process::exit(6);
    }
    let event = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if event < 0 {
        std::process::exit(5);
    }
    let event = unsafe { OwnedFd::from_raw_fd(event) };
    loop {
        let mut descriptor = libc::pollfd {
            fd: event.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut descriptor, 1, -1) } >= 0 {
            break;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
    if let Some(pid) = descendant {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
            libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0);
        }
    }
}

fn parse_fixture_arguments() -> (String, bool) {
    let mut arguments = std::env::args().skip(1);
    let mut ready_socket = None;
    let mut spawn_descendant = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--fixture-ready-socket" if ready_socket.is_none() => ready_socket = arguments.next(),
            "--fixture-spawn-descendant" if !spawn_descendant => spawn_descendant = true,
            _ => std::process::exit(2),
        }
    }
    let Some(ready_socket) = ready_socket.filter(|value| !value.is_empty()) else {
        std::process::exit(2);
    };
    (ready_socket, spawn_descendant)
}
