use super::*;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;

pub(crate) fn inspect_worker_identity(record: &PreCommitRuntimeRecord) -> WorkerIdentityStatus {
    let Some(pid) = record.worker_pid else {
        return WorkerIdentityStatus::Absent;
    };
    let Some(starttime) = record.worker_starttime else {
        return WorkerIdentityStatus::Indeterminate;
    };
    let Some(executable) = record.worker_executable else {
        return WorkerIdentityStatus::Indeterminate;
    };
    if proc_starttime(pid).is_none() {
        return WorkerIdentityStatus::Absent;
    }
    if proc_starttime(pid) == Some(starttime) && proc_executable(pid) == Some(executable) {
        WorkerIdentityStatus::Exact
    } else {
        WorkerIdentityStatus::Indeterminate
    }
}

pub(crate) fn kill_exact_pid(pid: u32) -> io::Result<()> {
    let result = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error);
    }
    for _ in 0..64 {
        if proc_state(pid) == Some('Z') {
            return Ok(());
        }
        let probe = unsafe { libc::kill(pid as i32, 0) };
        if probe != 0 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        std::thread::yield_now();
    }
    Err(io::Error::other("worker remained alive after SIGKILL"))
}

pub(crate) fn proc_starttime(pid: u32) -> Option<u64> {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()?
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

pub(crate) fn proc_executable(pid: u32) -> Option<(u64, u64)> {
    fs::metadata(format!("/proc/{pid}/exe"))
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

fn proc_state(pid: u32) -> Option<char> {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()?
        .rsplit_once(") ")?
        .1
        .chars()
        .next()
}
