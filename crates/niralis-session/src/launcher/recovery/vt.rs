use super::*;

pub(crate) fn recover_virtual_terminal(
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
    let path = format!("/dev/tty{}", identity.number);
    let c_path =
        CString::new(path.as_bytes()).map_err(|_| SupervisorRecoveryError::VtIdentityChanged)?;
    let tty_fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if tty_fd < 0 {
        return Err(SupervisorRecoveryError::VtOpenFailed(last_errno()));
    }
    let tty_fd = unsafe { OwnedFd::from_raw_fd(tty_fd) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(tty_fd.as_raw_fd(), &mut stat) } < 0
        || (stat.st_mode & libc::S_IFMT) != libc::S_IFCHR
        || libc::major(stat.st_rdev) as u32 != identity.device_major
        || libc::minor(stat.st_rdev) as u32 != identity.device_minor
    {
        return Err(SupervisorRecoveryError::VtIdentityChanged);
    }
    info!(
        vt = identity.number,
        previous_vt = identity.previous.number,
        "restoring session VT from supervisor recovery"
    );
    const KDSETMODE: libc::c_ulong = 0x4B3A;
    const KD_TEXT: libc::c_ulong = 0x00;
    const VT_SETMODE: libc::c_ulong = 0x5602;
    #[repr(C)]
    struct VtMode {
        mode: libc::c_char,
        waitv: libc::c_char,
        relsig: libc::c_short,
        acqsig: libc::c_short,
        frsig: libc::c_short,
    }
    let mode = VtMode {
        mode: 0,
        waitv: 0,
        relsig: 0,
        acqsig: 0,
        frsig: 0,
    };
    if unsafe { libc::ioctl(tty_fd.as_raw_fd(), KDSETMODE, KD_TEXT) } < 0
        || unsafe { libc::ioctl(tty_fd.as_raw_fd(), VT_SETMODE, &mode) } < 0
    {
        return Err(SupervisorRecoveryError::VtKernelRestoreFailed(last_errno()));
    }
    restore_default_selinux_context(&c_path)?;
    info!(tty = %path, "supervisor restored tty SELinux context");
    drop(tty_fd);
    let console =
        CString::new("/dev/console").map_err(|_| SupervisorRecoveryError::VtIdentityChanged)?;
    let console_fd = unsafe {
        libc::open(
            console.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if console_fd < 0 {
        return Err(SupervisorRecoveryError::VtOpenFailed(last_errno()));
    }
    let console_fd = unsafe { OwnedFd::from_raw_fd(console_fd) };
    const VT_ACTIVATE: libc::c_ulong = 0x5606;
    const VT_DISALLOCATE: libc::c_ulong = 0x5608;
    if unsafe {
        libc::ioctl(
            console_fd.as_raw_fd(),
            VT_ACTIVATE,
            identity.previous.number as libc::c_int,
        )
    } < 0
    {
        return Err(SupervisorRecoveryError::VtActivationFailed(last_errno()));
    }
    wait_for_previous_vt_activation(console_fd.as_raw_fd(), identity.previous.number)?;
    info!(
        expected_previous_vt = identity.previous.number,
        active_vt = active_vt_number(console_fd.as_raw_fd())?,
        "supervisor confirmed VT activation before disallocation"
    );
    if unsafe {
        libc::ioctl(
            console_fd.as_raw_fd(),
            VT_DISALLOCATE,
            identity.number as libc::c_int,
        )
    } < 0
    {
        let errno = last_errno();
        warn!(
            vt = identity.number,
            expected_previous_vt = identity.previous.number,
            active_vt = ?active_vt_number(console_fd.as_raw_fd()).ok(),
            errno,
            "supervisor VT disallocation failed"
        );
        return if errno == libc::EBUSY {
            Err(SupervisorRecoveryError::VtDisallocateBusy)
        } else {
            Err(SupervisorRecoveryError::VtDisallocateFailed(errno))
        };
    }
    info!("emergency VT recovery complete");
    Ok(())
}

pub(crate) fn wait_for_previous_vt_activation(
    console_fd: RawFd,
    expected: u32,
) -> Result<(), SupervisorRecoveryError> {
    const VT_GETSTATE: libc::c_ulong = 0x5603;
    #[repr(C)]
    struct VtState {
        active: libc::c_ushort,
        signal: libc::c_ushort,
        state: libc::c_ushort,
    }
    let active = || {
        let mut state = VtState {
            active: 0,
            signal: 0,
            state: 0,
        };
        if unsafe { libc::ioctl(console_fd, VT_GETSTATE, &mut state) } < 0 {
            Err(SupervisorRecoveryError::VtActivationFailed(last_errno()))
        } else {
            Ok(u32::from(state.active))
        }
    };
    if active()? == expected {
        return Ok(());
    }
    let path = CString::new("/sys/class/tty/tty0/active")
        .map_err(|_| SupervisorRecoveryError::VtActivationFailed(libc::EINVAL))?;
    let observer_fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if observer_fd < 0 {
        return Err(SupervisorRecoveryError::VtActivationFailed(last_errno()));
    }
    let observer = unsafe { OwnedFd::from_raw_fd(observer_fd) };
    let timer = MonotonicTimer::arm(Duration::from_secs(1))?;
    loop {
        let mut descriptors = [
            libc::pollfd {
                fd: observer.as_raw_fd(),
                events: libc::POLLPRI | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: timer.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
        if result < 0 {
            if last_errno() == libc::EINTR {
                continue;
            }
            return Err(SupervisorRecoveryError::VtActivationFailed(last_errno()));
        }
        if active()? == expected {
            return Ok(());
        }
        if descriptors[1].revents & libc::POLLIN != 0 {
            return Err(SupervisorRecoveryError::VtActivationFailed(libc::ETIMEDOUT));
        }
        if descriptors[0].revents & (libc::POLLPRI | libc::POLLERR) != 0 {
            let _ = unsafe { libc::lseek(observer.as_raw_fd(), 0, libc::SEEK_SET) };
            let mut discard = [0u8; 64];
            let _ = unsafe {
                libc::read(
                    observer.as_raw_fd(),
                    discard.as_mut_ptr().cast(),
                    discard.len(),
                )
            };
        }
    }
}

fn active_vt_number(console_fd: RawFd) -> Result<u32, SupervisorRecoveryError> {
    const VT_GETSTATE: libc::c_ulong = 0x5603;
    #[repr(C)]
    struct VtState {
        active: libc::c_ushort,
        signal: libc::c_ushort,
        state: libc::c_ushort,
    }
    let mut state = VtState {
        active: 0,
        signal: 0,
        state: 0,
    };
    if unsafe { libc::ioctl(console_fd, VT_GETSTATE, &mut state) } < 0 {
        Err(SupervisorRecoveryError::VtActivationFailed(last_errno()))
    } else {
        Ok(u32::from(state.active))
    }
}

pub(crate) fn restore_default_selinux_context(path: &CStr) -> Result<(), SupervisorRecoveryError> {
    let library = unsafe { Library::new("libselinux.so.1") }
        .map_err(|_| SupervisorRecoveryError::SelinuxRestoreFailed(libc::ENOENT))?;
    unsafe {
        let enabled: Symbol<unsafe extern "C" fn() -> libc::c_int> = library
            .get(b"is_selinux_enabled\0")
            .map_err(|_| SupervisorRecoveryError::SelinuxRestoreFailed(libc::ENOSYS))?;
        if enabled() == 0 {
            return Ok(());
        }
        let restore: Symbol<
            unsafe extern "C" fn(*const libc::c_char, libc::c_uint) -> libc::c_int,
        > = library
            .get(b"selinux_restorecon\0")
            .map_err(|_| SupervisorRecoveryError::SelinuxRestoreFailed(libc::ENOSYS))?;
        if restore(path.as_ptr(), 0) < 0 {
            return Err(SupervisorRecoveryError::SelinuxRestoreFailed(last_errno()));
        }
    }
    Ok(())
}

pub(crate) fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}
