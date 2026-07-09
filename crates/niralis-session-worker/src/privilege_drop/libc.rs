use std::ptr;

use super::{CredentialSyscalls, ObservedCredentials, SyscallError};

pub(crate) const HARD_MAX_SUPPLEMENTARY_GROUPS: usize = 65_536;
pub(crate) const HARD_MAX_OBSERVED_GROUPS: usize = HARD_MAX_SUPPLEMENTARY_GROUPS + 1;

pub(crate) fn bounded_max_observed_groups(expected: usize) -> usize {
    expected.min(HARD_MAX_OBSERVED_GROUPS)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LibcPrivilegeDropper;

impl super::PrivilegeDropper for LibcPrivilegeDropper {
    fn drop_privileges(
        &self,
        target: &super::PrivilegeDropTarget,
    ) -> Result<super::AppliedCredentials, super::PrivilegeDropError> {
        super::drop_privileges_with(self, target)
    }
}

impl CredentialSyscalls for LibcPrivilegeDropper {
    fn set_supplementary_groups(&self, groups: &[::libc::gid_t]) -> Result<(), SyscallError> {
        let (size, pointer) = if groups.is_empty() {
            (0, ptr::null())
        } else {
            (groups.len(), groups.as_ptr())
        };
        let size = ::libc::size_t::try_from(size).map_err(|_| SyscallError::InvalidCount)?;
        let result = unsafe { ::libc::setgroups(size, pointer) };
        if result == 0 {
            Ok(())
        } else {
            Err(SyscallError::Failed)
        }
    }

    fn set_primary_gid(&self, gid: libc::gid_t) -> Result<(), SyscallError> {
        if unsafe { ::libc::setgid(gid) } == 0 {
            Ok(())
        } else {
            Err(SyscallError::Failed)
        }
    }

    fn set_uid(&self, uid: libc::uid_t) -> Result<(), SyscallError> {
        if unsafe { ::libc::setuid(uid) } == 0 {
            Ok(())
        } else {
            Err(SyscallError::Failed)
        }
    }

    fn inspect_credentials(&self, max_groups: usize) -> Result<ObservedCredentials, SyscallError> {
        let max_groups = bounded_max_observed_groups(max_groups);
        let mut real_uid = 0;
        let mut effective_uid = 0;
        let mut saved_uid = 0;
        let mut real_gid = 0;
        let mut effective_gid = 0;
        let mut saved_gid = 0;
        if unsafe { ::libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0 {
            return Err(SyscallError::Failed);
        }
        if unsafe { ::libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0 {
            return Err(SyscallError::Failed);
        }
        let count = unsafe { ::libc::getgroups(0, ptr::null_mut()) };
        let count = usize::try_from(count).map_err(|_| SyscallError::InvalidCount)?;
        if count > max_groups {
            return Err(SyscallError::ObservedGroupCountExceeded);
        }
        let mut supplementary_gids = vec![0; count];
        let observed_count = if supplementary_gids.is_empty() {
            0
        } else {
            unsafe {
                ::libc::getgroups(
                    supplementary_gids.len() as ::libc::c_int,
                    supplementary_gids.as_mut_ptr(),
                )
            }
        };
        let observed_count =
            usize::try_from(observed_count).map_err(|_| SyscallError::InvalidCount)?;
        if observed_count > supplementary_gids.len() {
            return Err(SyscallError::InvalidCount);
        }
        supplementary_gids.truncate(observed_count);
        Ok(ObservedCredentials {
            real_uid,
            effective_uid,
            saved_uid,
            real_gid,
            effective_gid,
            saved_gid,
            supplementary_gids,
        })
    }
}
