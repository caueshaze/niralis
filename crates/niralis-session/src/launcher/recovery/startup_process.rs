use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

#[derive(Debug)]
pub(crate) enum PersistedProcessIdentity {
    OriginalStillAlive { pidfd: OwnedFd },
    OriginalGone,
    PidReused,
    Indeterminate,
}

pub(crate) fn rehydrate_process_identity(
    pid: u32,
    expected_starttime: Option<u64>,
    expected_executable: Option<(u64, u64)>,
    expected_cgroup: Option<&str>,
) -> PersistedProcessIdentity {
    if pid == 0 || expected_starttime.is_none() {
        return PersistedProcessIdentity::Indeterminate;
    }
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(_) => return PersistedProcessIdentity::OriginalGone,
    };
    let Some(starttime) = stat
        .rsplit_once(") ")
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return PersistedProcessIdentity::Indeterminate;
    };
    if Some(starttime) != expected_starttime {
        return PersistedProcessIdentity::PidReused;
    }
    if let Some(expected) = expected_executable {
        let Some(observed) = fs::metadata(format!("/proc/{pid}/exe"))
            .ok()
            .map(|metadata| (metadata.dev(), metadata.ino()))
        else {
            return PersistedProcessIdentity::Indeterminate;
        };
        if observed != expected {
            return PersistedProcessIdentity::PidReused;
        }
    }
    if let Some(expected) = expected_cgroup {
        let Some(observed) = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .and_then(|value| {
                value
                    .lines()
                    .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
            })
        else {
            return PersistedProcessIdentity::Indeterminate;
        };
        if observed != expected {
            return PersistedProcessIdentity::PidReused;
        }
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return PersistedProcessIdentity::Indeterminate;
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as std::os::fd::RawFd) };
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pollfd, 1, 0) } < 0 {
        return PersistedProcessIdentity::Indeterminate;
    }
    if pollfd.revents & libc::POLLIN != 0 {
        PersistedProcessIdentity::OriginalGone
    } else {
        PersistedProcessIdentity::OriginalStillAlive { pidfd }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_requires_matching_identity() {
        let pid = std::process::id();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let starttime = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap()
            .parse()
            .unwrap();
        let executable = fs::metadata(format!("/proc/{pid}/exe")).unwrap();
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
            .unwrap();
        assert!(matches!(
            rehydrate_process_identity(
                pid,
                Some(starttime),
                Some((executable.dev(), executable.ino())),
                Some(&cgroup)
            ),
            PersistedProcessIdentity::OriginalStillAlive { .. }
        ));
        assert!(matches!(
            rehydrate_process_identity(pid, Some(starttime + 1), None, None),
            PersistedProcessIdentity::PidReused
        ));
    }
}
