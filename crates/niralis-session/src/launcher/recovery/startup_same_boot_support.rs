use super::*;
use std::os::fd::AsRawFd;

pub(crate) fn send_sigterm(fd: i32) -> Result<(), ()> {
    if unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, libc::SIGTERM, 0, 0) } < 0 {
        Err(())
    } else {
        Ok(())
    }
}
pub(crate) fn wait_for_pidfd(fd: i32, timeout_ms: i32) -> Result<bool, ()> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    if result < 0 {
        Err(())
    } else {
        Ok(result > 0 && p.revents & libc::POLLIN != 0)
    }
}
pub(crate) fn wait_for_boundary_empty(pin: &SupervisorPinnedInvocationUnit) -> Result<(), ()> {
    let mut observer = CgroupEventsObserver::open(&pin.control_group).map_err(|_| ())?;
    let timer = MonotonicTimer::arm(EMERGENCY_BOUNDARY_TIMEOUT).map_err(|_| ())?;
    loop {
        if matches!(
            pin.boundary_state().map_err(|_| ())?,
            SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent
        ) {
            return Ok(());
        }
        let mut descriptors = [
            libc::pollfd {
                fd: observer.file.as_raw_fd(),
                events: libc::POLLPRI | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: timer.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) } < 0 {
            return Err(());
        }
        if descriptors[1].revents & libc::POLLIN != 0 {
            return Err(());
        }
        if descriptors[0].revents & (libc::POLLPRI | libc::POLLERR) != 0 {
            observer.refresh().map_err(|_| ())?;
        }
    }
}
pub(crate) fn startup_boundary_proof(
    pin: &SupervisorPinnedInvocationUnit,
    owner_watch: &OwnerWatch,
) -> Result<(), StartupRecoveryFailure> {
    owner_watch
        .stable()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    pin.validate_owner()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    if !matches!(
        pin.boundary_state()
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?,
        SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent
    ) {
        return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
    }
    ensure_outside_boundary(pin.worker_pid, &pin.control_group)
        .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    ensure_outside_boundary(pin.launcher_pid, &pin.control_group)
        .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    for _ in 0..2 {
        owner_watch
            .stable()
            .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
        let observation = pin
            .revalidate(true)
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
        if !unit_is_terminal(&observation)
            && !matches!(
                pin.boundary_state()
                    .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?,
                SupervisorBoundaryState::Absent
            )
        {
            return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
        }
    }
    owner_watch
        .stable()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    pin.validate_owner()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)
}
