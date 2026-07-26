use super::*;

/// Administrative A3.4.2 adapter. It is intentionally separate from the
/// SameBoot recovery target and accepts only the already validated admin call.
pub(crate) fn disallocate_virtual_terminal_once(
    target_vt: u32,
) -> Result<(), SupervisorRecoveryError> {
    let console =
        CString::new("/dev/tty0").map_err(|_| SupervisorRecoveryError::VtIdentityChanged)?;
    let raw = unsafe {
        libc::open(
            console.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(SupervisorRecoveryError::VtOpenFailed(last_errno()));
    }
    let console = unsafe { OwnedFd::from_raw_fd(raw) };
    super::disallocate_virtual_terminal_with_console(console.as_raw_fd(), target_vt)
}
