use super::*;

pub(crate) struct CgroupEventsObserver {
    pub(crate) file: fs::File,
}

impl CgroupEventsObserver {
    pub(crate) fn open(control_group: &str) -> Result<Self, SupervisorRecoveryError> {
        let path = cgroup_path(control_group)?.join("cgroup.events");
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| SupervisorRecoveryError::BoundaryObserverUnavailable)?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(SupervisorRecoveryError::BoundaryObserverUnavailable);
        }
        let mut value = Self {
            file: unsafe { fs::File::from_raw_fd(fd) },
        };
        value.refresh()?;
        Ok(value)
    }

    pub(crate) fn refresh(&mut self) -> Result<(), SupervisorRecoveryError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| SupervisorRecoveryError::BoundaryObserverUnavailable)?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(MAX_CGROUP_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SupervisorRecoveryError::BoundaryObserverUnavailable)?;
        if bytes.len() as u64 > MAX_CGROUP_FILE_BYTES || parse_populated(&bytes).is_none() {
            return Err(SupervisorRecoveryError::BoundaryObserverUnavailable);
        }
        Ok(())
    }
}

pub(crate) struct MonotonicTimer {
    pub(crate) fd: OwnedFd,
}

impl MonotonicTimer {
    pub(crate) fn arm(timeout: Duration) -> Result<Self, SupervisorRecoveryError> {
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(SupervisorRecoveryError::BoundaryObserverUnavailable);
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let specification = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: timeout.as_secs().min(i64::MAX as u64) as libc::time_t,
                tv_nsec: timeout.subsec_nanos() as libc::c_long,
            },
        };
        if unsafe { libc::timerfd_settime(fd.as_raw_fd(), 0, &specification, std::ptr::null_mut()) }
            < 0
        {
            return Err(SupervisorRecoveryError::BoundaryObserverUnavailable);
        }
        Ok(Self { fd })
    }
}
