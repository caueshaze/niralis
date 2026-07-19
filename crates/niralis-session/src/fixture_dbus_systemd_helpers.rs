use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::RawFd;
use std::path::PathBuf;

pub(crate) fn append(path: &PathBuf, value: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(value.as_bytes());
    }
}

pub(crate) fn send_pidfd(pid: u32, expected_starttime: u64) -> zbus::fdo::Result<()> {
    if starttime(pid) != Some(expected_starttime) {
        return Err(zbus::fdo::Error::Failed("pid identity".into()));
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) as RawFd };
    if fd < 0 {
        return Err(zbus::fdo::Error::Failed("pidfd".into()));
    }
    let result = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, libc::SIGKILL, 0, 0) };
    unsafe {
        libc::close(fd);
    }
    if result == 0 {
        Ok(())
    } else {
        Err(zbus::fdo::Error::Failed("signal".into()))
    }
}

pub(crate) fn starttime(pid: u32) -> Option<u64> {
    let value = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    value
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

pub(crate) fn parse_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() != 32 {
        return None;
    }
    (0..16)
        .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

pub(crate) fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
