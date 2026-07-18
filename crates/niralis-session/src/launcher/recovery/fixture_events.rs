use super::*;

pub(crate) fn fixture_eventfd() -> Result<OwnedFd, SupervisorRecoveryError> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        Err(SupervisorRecoveryError::InvalidRecord)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) fn signal_fixture_completion(event: &OwnedFd) {
    let value = 1u64.to_ne_bytes();
    let _ = unsafe { libc::write(event.as_raw_fd(), value.as_ptr().cast(), value.len()) };
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) fn wait_fixture_event(event: &OwnedFd) -> Result<(), SupervisorRecoveryError> {
    let mut descriptor = libc::pollfd {
        fd: event.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut descriptor, 1, -1) };
        if result < 0 && last_errno() == libc::EINTR {
            continue;
        }
        if result <= 0 || descriptor.revents & libc::POLLIN == 0 {
            return Err(SupervisorRecoveryError::InvalidRecord);
        }
        let mut value = 0u64;
        let read = unsafe {
            libc::read(
                event.as_raw_fd(),
                (&mut value as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        return if read == std::mem::size_of::<u64>() as isize {
            Ok(())
        } else {
            Err(SupervisorRecoveryError::InvalidRecord)
        };
    }
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) fn fixture_pidfd_kill(pid: u32) -> Result<(), SupervisorRecoveryError> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return if last_errno() == libc::ESRCH {
            Ok(())
        } else {
            Err(SupervisorRecoveryError::InvalidRecord)
        };
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 && last_errno() != libc::ESRCH {
        return Err(SupervisorRecoveryError::InvalidRecord);
    }
    let mut descriptor = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut descriptor, 1, 2_000) };
        if ready < 0 && last_errno() == libc::EINTR {
            continue;
        }
        return if ready == 1 && descriptor.revents & libc::POLLIN != 0 {
            Ok(())
        } else {
            Err(SupervisorRecoveryError::BoundaryTimedOut)
        };
    }
}
