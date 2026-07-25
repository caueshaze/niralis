use super::vt_busy_holders::enumerate_holders;
use super::vt_busy_support::{boottime_ns, device_identity, push_failure};
use super::*;
use crate::{DeviceIdentity, VtBusyClassification, VtBusyProvenance, VtInspectionFailure};
use std::fs;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VtKnownProcess {
    pub(crate) pid: u32,
    pub(crate) starttime: Option<u64>,
}

pub(crate) fn inspect_vt_busy(target_vt: u32, known: &[VtKnownProcess]) -> VtBusyProvenance {
    let mut failures = Vec::new();
    let target = target_device(target_vt, &mut failures);
    let active = active_vt(&mut failures);
    let mut holders = Vec::new();
    let mut holders_truncated = false;
    if let Some(target) = &target {
        enumerate_holders(target, &mut holders, &mut holders_truncated, &mut failures);
    }
    let target_is_foreground = active.map(|value| value == target_vt);
    let internal = holders.iter().any(|holder| {
        known.iter().any(|process| {
            process.pid == holder.pid
                && process.starttime.is_some()
                && process.starttime == Some(holder.starttime)
        })
    });
    let classification = if internal {
        VtBusyClassification::InternalNiralisHolder
    } else if target_is_foreground == Some(true) {
        VtBusyClassification::TargetStillForeground
    } else if target.is_none() || active.is_none() || !failures.is_empty() {
        VtBusyClassification::InspectionUnavailable
    } else if holders.len() > 1 || holders_truncated {
        VtBusyClassification::MultipleVisibleUserspaceHolders
    } else if holders.len() == 1 {
        VtBusyClassification::VisibleUserspaceHolder
    } else {
        VtBusyClassification::KernelBusyUnattributed
    };
    VtBusyProvenance {
        target_vt,
        observed_active_vt: active,
        target_is_foreground,
        target_device: target,
        visible_holders: holders,
        holders_truncated,
        inspection_failures: failures,
        classification,
        captured_at_boottime_ns: boottime_ns(),
    }
}

fn target_device(
    target_vt: u32,
    failures: &mut Vec<VtInspectionFailure>,
) -> Option<DeviceIdentity> {
    match fs::metadata(format!("/dev/tty{target_vt}")) {
        Ok(metadata) if metadata.file_type().is_char_device() => {
            Some(device_identity(metadata.rdev()))
        }
        Ok(_) => {
            push_failure(
                failures,
                VtInspectionFailure::TargetDevice {
                    errno: libc::ENOTTY,
                },
            );
            None
        }
        Err(error) => {
            push_failure(
                failures,
                VtInspectionFailure::TargetDevice {
                    errno: error.raw_os_error().unwrap_or(libc::EIO),
                },
            );
            None
        }
    }
}

fn active_vt(failures: &mut Vec<VtInspectionFailure>) -> Option<u32> {
    let path = std::ffi::CString::new("/dev/tty0").unwrap();
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY,
        )
    };
    if fd < 0 {
        push_failure(
            failures,
            VtInspectionFailure::ActiveVt {
                errno: last_errno(),
            },
        );
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
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
        push_failure(
            failures,
            VtInspectionFailure::ActiveVt {
                errno: last_errno(),
            },
        );
        None
    } else {
        Some(u32::from(state.active))
    }
}
