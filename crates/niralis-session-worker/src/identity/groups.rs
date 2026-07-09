use std::ffi::CString;

use libc::{c_int, gid_t};

use super::{GroupResolutionError, SupplementaryGroupsResolver, UnixIdentity};

const DEFAULT_GROUP_CAPACITY: usize = 16;
const MAX_GROUP_LOOKUP_ATTEMPTS: usize = 8;
const HARD_MAX_SUPPLEMENTARY_GROUPS: usize = 65_536;

#[derive(Debug, Default, Clone, Copy)]
pub struct NssSupplementaryGroupsResolver;

impl SupplementaryGroupsResolver for NssSupplementaryGroupsResolver {
    fn resolve(&self, identity: &UnixIdentity) -> Result<Vec<u32>, GroupResolutionError> {
        resolve_groups_with(identity, &LibcGroupListLookup)
    }
}

pub(crate) trait GroupListLookup {
    fn lookup(
        &self,
        username: &CString,
        primary_gid: gid_t,
        groups: &mut [gid_t],
        ngroups: &mut c_int,
    ) -> GroupLookupResult;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupLookupResult {
    Success,
    BufferTooSmall,
    Failure,
}

pub(crate) fn classify_getgrouplist_result(result: c_int) -> GroupLookupResult {
    match result {
        -1 => GroupLookupResult::BufferTooSmall,
        value if value >= 0 => GroupLookupResult::Success,
        _ => GroupLookupResult::Failure,
    }
}

struct LibcGroupListLookup;

impl GroupListLookup for LibcGroupListLookup {
    fn lookup(
        &self,
        username: &CString,
        primary_gid: gid_t,
        groups: &mut [gid_t],
        ngroups: &mut c_int,
    ) -> GroupLookupResult {
        let mut count = c_int::try_from(groups.len()).unwrap_or(c_int::MAX);
        let result = unsafe {
            libc::getgrouplist(
                username.as_ptr(),
                primary_gid,
                groups.as_mut_ptr(),
                &mut count,
            )
        };
        *ngroups = count;
        classify_getgrouplist_result(result)
    }
}

pub(crate) fn resolve_groups_with<L: GroupListLookup>(
    identity: &UnixIdentity,
    lookup: &L,
) -> Result<Vec<u32>, GroupResolutionError> {
    let username = CString::new(identity.username.as_str())
        .map_err(|_| GroupResolutionError::InvalidUsername)?;
    let supplementary_limit = supplementary_group_limit();
    let raw_limit = supplementary_limit
        .checked_add(1)
        .ok_or(GroupResolutionError::TooManyGroups)?;
    let primary_gid =
        gid_t::try_from(identity.gid).map_err(|_| GroupResolutionError::LookupFailed)?;
    let mut capacity = DEFAULT_GROUP_CAPACITY.min(raw_limit).max(1);

    for _ in 0..MAX_GROUP_LOOKUP_ATTEMPTS {
        let mut groups = vec![0 as gid_t; capacity];
        let mut ngroups =
            c_int::try_from(capacity).map_err(|_| GroupResolutionError::TooManyGroups)?;
        match lookup.lookup(&username, primary_gid, &mut groups, &mut ngroups) {
            GroupLookupResult::Success => {
                let count = valid_count(ngroups, capacity, raw_limit)?;
                return normalize_groups(&groups[..count], identity.gid, supplementary_limit);
            }
            GroupLookupResult::BufferTooSmall => {
                let required = required_capacity(ngroups, capacity, raw_limit)?;
                capacity = required;
            }
            GroupLookupResult::Failure => return Err(GroupResolutionError::LookupFailed),
        }
    }

    Err(GroupResolutionError::LookupFailed)
}

fn required_capacity(
    ngroups: c_int,
    capacity: usize,
    raw_limit: usize,
) -> Result<usize, GroupResolutionError> {
    let required = usize::try_from(ngroups).map_err(|_| GroupResolutionError::LookupFailed)?;
    if required <= capacity {
        return Err(GroupResolutionError::LookupFailed);
    }
    if required > raw_limit {
        return Err(GroupResolutionError::TooManyGroups);
    }
    Ok(required)
}

fn valid_count(
    ngroups: c_int,
    capacity: usize,
    raw_limit: usize,
) -> Result<usize, GroupResolutionError> {
    let count = usize::try_from(ngroups).map_err(|_| GroupResolutionError::LookupFailed)?;
    if count > capacity || count > raw_limit {
        return Err(GroupResolutionError::LookupFailed);
    }
    Ok(count)
}

fn normalize_groups(
    groups: &[gid_t],
    primary_gid: u32,
    supplementary_limit: usize,
) -> Result<Vec<u32>, GroupResolutionError> {
    let mut result = groups
        .iter()
        .map(|gid| u32::try_from(*gid).map_err(|_| GroupResolutionError::LookupFailed))
        .collect::<Result<Vec<_>, _>>()?;
    result.sort_unstable();
    result.dedup();
    result.retain(|gid| *gid != primary_gid);
    if result.len() > supplementary_limit {
        return Err(GroupResolutionError::TooManyGroups);
    }
    Ok(result)
}

fn supplementary_group_limit() -> usize {
    let raw = unsafe { libc::sysconf(libc::_SC_NGROUPS_MAX) };
    usize::try_from(raw)
        .ok()
        .filter(|limit| *limit > 0)
        .map_or(HARD_MAX_SUPPLEMENTARY_GROUPS, |limit| {
            limit.min(HARD_MAX_SUPPLEMENTARY_GROUPS)
        })
}
