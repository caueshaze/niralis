use super::vt_busy_support::{device_identity, proc_starttime, push_failure};
use crate::{
    DeviceIdentity, ExecutableIdentity, VtHolderIdentity, VtInspectionFailure, MAX_VT_BUSY_HOLDERS,
};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

pub(super) fn enumerate_holders(
    target: &DeviceIdentity,
    holders: &mut Vec<VtHolderIdentity>,
    truncated: &mut bool,
    failures: &mut Vec<VtInspectionFailure>,
) {
    let target_path = std::path::PathBuf::from(format!("/dev/tty{}", target.minor));
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(error) => {
            push_failure(
                failures,
                VtInspectionFailure::ProcEnumeration {
                    errno: error.raw_os_error().unwrap_or(libc::EIO),
                },
            );
            return;
        }
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Some(starttime) = proc_starttime(pid) else {
            continue;
        };
        let uid = match fs::metadata(format!("/proc/{pid}")) {
            Ok(metadata) => metadata.uid(),
            Err(error) => {
                push_failure(
                    failures,
                    VtInspectionFailure::ProcessIdentity {
                        pid,
                        errno: error.raw_os_error().unwrap_or(libc::EIO),
                    },
                );
                continue;
            }
        };
        let fds = match fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(fds) => fds,
            Err(error) => {
                if error.raw_os_error() != Some(libc::ENOENT) {
                    push_failure(
                        failures,
                        VtInspectionFailure::ProcessIdentity {
                            pid,
                            errno: error.raw_os_error().unwrap_or(libc::EIO),
                        },
                    );
                }
                continue;
            }
        };
        for fd in fds.flatten() {
            let Ok(fd_number) = fd.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let link = match fs::read_link(fd.path()) {
                Ok(link) => link,
                Err(error) => {
                    if error.raw_os_error() != Some(libc::ENOENT) {
                        push_failure(
                            failures,
                            VtInspectionFailure::FdInspection {
                                pid,
                                fd: fd_number,
                                errno: error.raw_os_error().unwrap_or(libc::EIO),
                            },
                        );
                    }
                    continue;
                }
            };
            // Read link text first. Only a canonical target-VT candidate is
            // stat'd; rdev comparison below, not the path, proves identity.
            if link != target_path {
                continue;
            }
            let metadata = match fs::metadata(fd.path()) {
                Ok(metadata) => metadata,
                Err(error) => {
                    if error.raw_os_error() != Some(libc::ENOENT) {
                        push_failure(
                            failures,
                            VtInspectionFailure::FdInspection {
                                pid,
                                fd: fd_number,
                                errno: error.raw_os_error().unwrap_or(libc::EIO),
                            },
                        );
                    }
                    continue;
                }
            };
            if !metadata.file_type().is_char_device()
                || device_identity(metadata.rdev()) != *target
                || proc_starttime(pid) != Some(starttime)
            {
                continue;
            }
            if holders.len() == MAX_VT_BUSY_HOLDERS {
                *truncated = true;
                continue;
            }
            holders.push(VtHolderIdentity {
                pid,
                starttime,
                uid,
                fd: fd_number,
                executable: fs::metadata(format!("/proc/{pid}/exe")).ok().map(|m| {
                    ExecutableIdentity {
                        device: m.dev(),
                        inode: m.ino(),
                    }
                }),
                cgroup: fs::read_to_string(format!("/proc/{pid}/cgroup"))
                    .ok()
                    .and_then(|v| {
                        v.lines()
                            .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
                    }),
                session_id: None,
            });
        }
    }
}
