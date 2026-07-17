
fn release_allocated_terminal(
    operations: &mut dyn VtReleaseOperations,
    allocated: u32,
    previous: u32,
    wait: Duration,
) -> Result<(), VirtualTerminalError> {
    let active =
        operations
            .active()
            .map_err(|errno| VirtualTerminalError::CleanupOperationFailed {
                stage: "query_active",
                errno,
            })?;
    if active == allocated {
        operations.activate(previous).map_err(|errno| {
            VirtualTerminalError::CleanupOperationFailed {
                stage: "restore_previous",
                errno,
            }
        })?;
        let deadline = Instant::now() + wait;
        loop {
            let active = operations.active().map_err(|errno| {
                VirtualTerminalError::CleanupOperationFailed {
                    stage: "confirm_previous",
                    errno,
                }
            })?;
            if active == previous {
                break;
            }
            if Instant::now() >= deadline {
                return Err(VirtualTerminalError::CleanupTimedOut);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    operations.close_terminal();
    operations.disallocate(allocated).map_err(|errno| {
        VirtualTerminalError::CleanupOperationFailed {
            stage: "disallocate",
            errno,
        }
    })
}

#[repr(C)]
struct VtState {
    active: libc::c_ushort,
    signal: libc::c_ushort,
    state: libc::c_ushort,
}

fn open_device(path: &CStr) -> Result<OwnedFd, VirtualTerminalError> {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(VirtualTerminalError::DeviceOpenFailed {
            path: path.to_string_lossy().into_owned(),
            errno: last_errno(),
        });
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: RawFd) -> Result<libc::stat, VirtualTerminalError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } < 0 {
        return Err(VirtualTerminalError::DeviceMetadataFailed(last_errno()));
    }
    Ok(stat)
}

fn last_errno() -> libc::c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}
