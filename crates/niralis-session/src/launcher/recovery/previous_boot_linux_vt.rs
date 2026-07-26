use super::*;
use crate::launcher::recovery::vt_busy_holders::enumerate_holders;
use crate::launcher::recovery::vt_busy_support::device_identity;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

pub(super) fn inspect_vt(vt: u32) -> Result<CurrentVtFacts, PreviousBootInspectionError> {
    let active_vt = read_active_vt()?;
    let metadata = fs::metadata(format!("/dev/tty{vt}"))
        .map_err(|_| PreviousBootInspectionError::Unavailable)?;
    let target = device_identity(metadata.rdev());
    let mut holders = Vec::new();
    let mut truncated = false;
    let mut failures = Vec::new();
    enumerate_holders(&target, &mut holders, &mut truncated, &mut failures);
    let disposition = if active_vt == Some(vt) {
        CurrentVtDisposition::Foreground
    } else if !holders.is_empty() {
        CurrentVtDisposition::VisibleCurrentHolder
    } else {
        CurrentVtDisposition::NotForegroundAndUnused
    };
    Ok(CurrentVtFacts {
        target_vt: vt,
        active_vt,
        disposition,
        inspection_complete: !truncated && failures.is_empty(),
        visible_holders: holders,
    })
}

fn read_active_vt() -> Result<Option<u32>, PreviousBootInspectionError> {
    let fd = fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty0")
        .map_err(|_| PreviousBootInspectionError::Unavailable)?;
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
    if unsafe { libc::ioctl(fd.as_raw_fd(), 0x5603, &mut state) } < 0 {
        return Err(PreviousBootInspectionError::Unavailable);
    }
    Ok(Some(u32::from(state.active)))
}
