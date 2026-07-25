use crate::{DeviceIdentity, VtInspectionFailure, MAX_VT_INSPECTION_FAILURES};
use std::fs;

pub(super) fn device_identity(rdev: u64) -> DeviceIdentity {
    DeviceIdentity {
        major: libc::major(rdev),
        minor: libc::minor(rdev),
        character_device: true,
    }
}

pub(super) fn proc_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, tail) = stat.rsplit_once(") ")?;
    tail.split_whitespace().nth(19)?.parse().ok()
}

pub(super) fn boottime_ns() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } == 0 {
        (value.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(value.tv_nsec as u64)
    } else {
        0
    }
}

pub(super) fn push_failure(failures: &mut Vec<VtInspectionFailure>, failure: VtInspectionFailure) {
    if failures.len() < MAX_VT_INSPECTION_FAILURES {
        failures.push(failure)
    }
}
