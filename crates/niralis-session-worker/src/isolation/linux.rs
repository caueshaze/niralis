use super::{
    CapabilityState, FdSanitizationError, InheritedFdSanitizer, PostDropAuditError,
    PostDropAuditor, PostDropIsolationProof, HARD_MAX_CAPABILITY_ID,
};
use std::fs;
use std::os::fd::RawFd;

const CAPGET_VERSION: u32 = 0x2008_0522;
const PR_CAPBSET_READ: libc::c_int = 23;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_IS_SET: libc::c_ulong = 1;
const PR_GET_SECUREBITS: libc::c_int = 27;
const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxInheritedFdSanitizer;

impl InheritedFdSanitizer for LinuxInheritedFdSanitizer {
    fn sanitize(&self) -> Result<(), FdSanitizationError> {
        let result =
            unsafe { libc::syscall(libc::SYS_close_range as libc::c_long, 3, u32::MAX, 0) };
        if result == 0 {
            return Ok(());
        }
        let entries = fs::read_dir("/proc/self/fd").map_err(|_| FdSanitizationError::Failed)?;
        let mut fds = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| FdSanitizationError::Failed)?;
            if let Ok(fd) = entry.file_name().to_string_lossy().parse::<RawFd>() {
                if fd >= 3 {
                    fds.push(fd);
                }
            }
        }
        for fd in fds {
            unsafe {
                libc::close(fd);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxPostDropAuditor;

impl PostDropAuditor for LinuxPostDropAuditor {
    fn audit(&self) -> Result<PostDropIsolationProof, PostDropAuditError> {
        let last = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .map_err(|_| PostDropAuditError::Failed)?
            .trim()
            .parse::<u32>()
            .map_err(|_| PostDropAuditError::Failed)?;
        if last > HARD_MAX_CAPABILITY_ID {
            return Err(PostDropAuditError::UnsupportedCapabilityRange);
        }
        let mut header = CapHeader {
            version: CAPGET_VERSION,
            pid: 0,
        };
        let words = (last as usize / 32) + 1;
        let mut data = vec![
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0
            };
            words
        ];
        if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
            return Err(PostDropAuditError::Failed);
        }
        let sets =
            |which: fn(CapData) -> u32| -> Vec<u32> { bits(data.iter().copied().map(which), last) };
        let mut ambient = Vec::new();
        let mut bounding = Vec::new();
        for cap in 0..=last {
            let ambient_set = unsafe {
                libc::syscall(
                    libc::SYS_prctl,
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_IS_SET,
                    cap,
                    0,
                    0,
                )
            };
            if ambient_set < 0 {
                return Err(PostDropAuditError::Failed);
            }
            if ambient_set == 1 {
                ambient.push(cap);
            }
            let bound = unsafe { libc::syscall(libc::SYS_prctl, PR_CAPBSET_READ, cap, 0, 0, 0) };
            if bound < 0 {
                return Err(PostDropAuditError::Failed);
            }
            if bound == 1 {
                bounding.push(cap);
            }
        }
        let securebits = prctl_value(PR_GET_SECUREBITS)? as u32;
        let no_new_privs = prctl_value(PR_GET_NO_NEW_PRIVS)? != 0;
        let open_fds = open_fds()?;
        Ok(PostDropIsolationProof {
            capabilities: CapabilityState {
                effective: sets(|d| d.effective),
                permitted: sets(|d| d.permitted),
                inheritable: sets(|d| d.inheritable),
                ambient,
                bounding,
                cap_last_cap: last,
            },
            securebits,
            no_new_privs,
            open_fds,
        })
    }
}

fn bits<I: Iterator<Item = u32>>(words: I, last: u32) -> Vec<u32> {
    let mut result = Vec::new();
    for (word, value) in words.enumerate() {
        for bit in 0..32 {
            let cap = (word as u32) * 32 + bit;
            if cap <= last && value & (1 << bit) != 0 {
                result.push(cap);
            }
        }
    }
    result
}

fn prctl_value(option: libc::c_int) -> Result<libc::c_long, PostDropAuditError> {
    let value = unsafe { libc::syscall(libc::SYS_prctl, option, 0, 0, 0, 0) };
    if value < 0 {
        Err(PostDropAuditError::Failed)
    } else {
        Ok(value)
    }
}

fn open_fds() -> Result<Vec<i32>, PostDropAuditError> {
    let candidates = {
        let entries = fs::read_dir("/proc/self/fd").map_err(|_| PostDropAuditError::Failed)?;
        let mut candidates = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| PostDropAuditError::Failed)?;
            if let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() {
                candidates.push(fd);
            }
        }
        candidates
    };
    let mut result = Vec::new();
    for fd in candidates {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
            result.push(fd);
        }
    }
    result.sort_unstable();
    result.dedup();
    Ok(result)
}
