use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupVtRecoveryState {
    Recovered,
    NeedsRecovery,
}

pub(crate) fn inspect_startup_virtual_terminal(
    identity: &SupervisorVtIdentity,
) -> Result<StartupVtRecoveryState, SupervisorRecoveryError> {
    validate_vt_identity(identity)?;
    let path = CString::new(format!("/dev/tty{}", identity.number))
        .map_err(|_| SupervisorRecoveryError::VtIdentityChanged)?;
    let tty_fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if tty_fd < 0 {
        return Err(SupervisorRecoveryError::VtOpenFailed(last_errno()));
    }
    let tty_fd = unsafe { OwnedFd::from_raw_fd(tty_fd) };
    validate_tty_device(tty_fd.as_raw_fd(), identity)?;
    let console =
        CString::new("/dev/tty0").map_err(|_| SupervisorRecoveryError::VtIdentityChanged)?;
    let console_fd = unsafe {
        libc::open(
            console.as_ptr(),
            libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if console_fd < 0 {
        return Err(SupervisorRecoveryError::VtOpenFailed(last_errno()));
    }
    let console_fd = unsafe { OwnedFd::from_raw_fd(console_fd) };
    let state = read_vt_state(console_fd.as_raw_fd())?;
    if u32::from(state.active) != identity.previous.number || !(1..=16).contains(&identity.number) {
        Err(SupervisorRecoveryError::VtIdentityChanged)
    } else if vt_state_proves_target_disallocated(state.state, identity.number) {
        Ok(StartupVtRecoveryState::Recovered)
    } else {
        Ok(StartupVtRecoveryState::NeedsRecovery)
    }
}

#[repr(C)]
struct VtState {
    active: libc::c_ushort,
    signal: libc::c_ushort,
    state: libc::c_ushort,
}

fn read_vt_state(console_fd: RawFd) -> Result<VtState, SupervisorRecoveryError> {
    const VT_GETSTATE: libc::c_ulong = 0x5603;
    let mut state = VtState {
        active: 0,
        signal: 0,
        state: 0,
    };
    if unsafe { libc::ioctl(console_fd, VT_GETSTATE, &mut state) } < 0 {
        Err(SupervisorRecoveryError::VtActivationFailed(last_errno()))
    } else {
        Ok(state)
    }
}

pub(crate) fn validate_vt_identity(
    identity: &SupervisorVtIdentity,
) -> Result<(), SupervisorRecoveryError> {
    if identity.seat != "seat0"
        || !(1..=63).contains(&identity.number)
        || !(1..=63).contains(&identity.previous.number)
        || identity.number == identity.previous.number
        || identity.device_major != 4
        || identity.device_minor != identity.number
    {
        return Err(SupervisorRecoveryError::VtIdentityChanged);
    }
    Ok(())
}

pub(crate) fn validate_tty_device(
    fd: RawFd,
    identity: &SupervisorVtIdentity,
) -> Result<(), SupervisorRecoveryError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } < 0
        || (stat.st_mode & libc::S_IFMT) != libc::S_IFCHR
        || libc::major(stat.st_rdev) as u32 != identity.device_major
        || libc::minor(stat.st_rdev) as u32 != identity.device_minor
    {
        return Err(SupervisorRecoveryError::VtIdentityChanged);
    }
    Ok(())
}

fn vt_state_proves_target_disallocated(allocated: u16, target: u32) -> bool {
    1u16.checked_shl(target - 1)
        .is_some_and(|mask| allocated & mask == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_vt_proof_requires_previous_active_and_target_unallocated() {
        assert!(vt_state_proves_target_disallocated(0, 2));
        assert!(!vt_state_proves_target_disallocated(1 << 1, 2));
        assert!(!vt_state_proves_target_disallocated(0, 17));
    }
}
