mod libc;

use ::libc::{gid_t, uid_t};
use thiserror::Error;

use crate::ResolvedUnixCredentials;

pub use libc::LibcPrivilegeDropper;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedCredentials {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeDropTarget {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
}

impl From<&ResolvedUnixCredentials> for PrivilegeDropTarget {
    fn from(credentials: &ResolvedUnixCredentials) -> Self {
        Self {
            uid: credentials.identity.uid,
            gid: credentials.identity.gid,
            supplementary_gids: credentials.supplementary_gids.clone(),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PrivilegeDropError {
    #[error("invalid user ID")]
    InvalidUid,
    #[error("invalid group ID")]
    InvalidGid,
    #[error("invalid supplementary group ID")]
    InvalidSupplementaryGid,
    #[error("invalid supplementary group invariants")]
    InvalidSupplementaryGroups,
    #[error("root UID is not a valid privilege-drop target")]
    RootUidDisallowed,
    #[error("failed to set supplementary groups")]
    SetGroupsFailed,
    #[error("failed to set primary group ID")]
    SetGidFailed,
    #[error("failed to set user ID")]
    SetUidFailed,
    #[error("failed to inspect effective credentials")]
    VerificationFailed,
    #[error("effective credentials do not match requested credentials")]
    CredentialMismatch,
}

pub trait PrivilegeDropper: Send + Sync {
    /// # Safety contract
    ///
    /// This primitive is intended to run only inside a dedicated,
    /// single-threaded session child before executing user-controlled code.
    /// It must not run in the privileged PAM supervisor or in the main daemon.
    fn drop_privileges(
        &self,
        target: &PrivilegeDropTarget,
    ) -> Result<AppliedCredentials, PrivilegeDropError>;
}

pub(crate) trait CredentialSyscalls {
    fn set_supplementary_groups(&self, groups: &[gid_t]) -> Result<(), SyscallError>;

    fn set_primary_gid(&self, gid: gid_t) -> Result<(), SyscallError>;

    fn set_uid(&self, uid: uid_t) -> Result<(), SyscallError>;

    fn inspect_credentials(&self, max_groups: usize) -> Result<ObservedCredentials, SyscallError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservedCredentials {
    pub real_uid: uid_t,
    pub effective_uid: uid_t,
    pub saved_uid: uid_t,
    pub real_gid: gid_t,
    pub effective_gid: gid_t,
    pub saved_gid: gid_t,
    pub supplementary_gids: Vec<gid_t>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyscallError {
    Failed,
    InvalidCount,
    ObservedGroupCountExceeded,
}

pub(crate) fn drop_privileges_with<S: CredentialSyscalls>(
    syscalls: &S,
    target: &PrivilegeDropTarget,
) -> Result<AppliedCredentials, PrivilegeDropError> {
    if target.uid == 0 {
        return Err(PrivilegeDropError::RootUidDisallowed);
    }
    let uid = uid_t::try_from(target.uid).map_err(|_| PrivilegeDropError::InvalidUid)?;
    let gid = gid_t::try_from(target.gid).map_err(|_| PrivilegeDropError::InvalidGid)?;
    let mut supplementary_gids = Vec::with_capacity(target.supplementary_gids.len());
    for supplementary_gid in &target.supplementary_gids {
        supplementary_gids.push(
            gid_t::try_from(*supplementary_gid)
                .map_err(|_| PrivilegeDropError::InvalidSupplementaryGid)?,
        );
    }
    if target
        .supplementary_gids
        .windows(2)
        .any(|window| window[0] >= window[1])
        || target
            .supplementary_gids
            .iter()
            .any(|supplementary_gid| *supplementary_gid == target.gid)
    {
        return Err(PrivilegeDropError::InvalidSupplementaryGroups);
    }
    let max_groups = target
        .supplementary_gids
        .len()
        .checked_add(1)
        .ok_or(PrivilegeDropError::VerificationFailed)?;

    syscalls
        .set_supplementary_groups(&supplementary_gids)
        .map_err(|_| PrivilegeDropError::SetGroupsFailed)?;
    syscalls
        .set_primary_gid(gid)
        .map_err(|_| PrivilegeDropError::SetGidFailed)?;
    syscalls
        .set_uid(uid)
        .map_err(|_| PrivilegeDropError::SetUidFailed)?;
    let observed = match syscalls.inspect_credentials(max_groups) {
        Ok(observed) => observed,
        Err(SyscallError::ObservedGroupCountExceeded) => {
            return Err(PrivilegeDropError::CredentialMismatch)
        }
        Err(_) => return Err(PrivilegeDropError::VerificationFailed),
    };

    if observed.real_uid != uid
        || observed.effective_uid != uid
        || observed.saved_uid != uid
        || observed.real_gid != gid
        || observed.effective_gid != gid
        || observed.saved_gid != gid
    {
        return Err(PrivilegeDropError::CredentialMismatch);
    }
    let observed_uid =
        u32::try_from(observed.real_uid).map_err(|_| PrivilegeDropError::VerificationFailed)?;
    let observed_gid =
        u32::try_from(observed.real_gid).map_err(|_| PrivilegeDropError::VerificationFailed)?;
    let mut observed_groups = observed.supplementary_gids;
    observed_groups.sort_unstable();
    observed_groups.dedup();
    observed_groups.retain(|observed_gid| *observed_gid != gid);
    if observed_groups != supplementary_gids {
        return Err(PrivilegeDropError::CredentialMismatch);
    }

    let observed_supplementary_gids = observed_groups
        .into_iter()
        .map(|gid| u32::try_from(gid).map_err(|_| PrivilegeDropError::VerificationFailed))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(AppliedCredentials {
        uid: observed_uid,
        gid: observed_gid,
        supplementary_gids: observed_supplementary_gids,
    })
}

#[cfg(test)]
mod tests;
