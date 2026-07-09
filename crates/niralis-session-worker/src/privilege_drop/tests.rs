use ::libc::{gid_t, uid_t};
use std::sync::Mutex;

use super::libc::{
    bounded_max_observed_groups, HARD_MAX_OBSERVED_GROUPS, HARD_MAX_SUPPLEMENTARY_GROUPS,
};
use super::*;
use crate::{ResolvedUnixCredentials, UnixIdentity};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    SetGroups(Vec<gid_t>),
    SetGid(gid_t),
    SetUid(uid_t),
    Inspect(usize),
}

struct RecordingSyscalls {
    calls: Mutex<Vec<Call>>,
    setgroups: Result<(), SyscallError>,
    setgid: Result<(), SyscallError>,
    setuid: Result<(), SyscallError>,
    observed: Result<ObservedCredentials, SyscallError>,
}

impl CredentialSyscalls for RecordingSyscalls {
    fn set_supplementary_groups(&self, groups: &[gid_t]) -> Result<(), SyscallError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::SetGroups(groups.to_vec()));
        self.setgroups
    }

    fn set_primary_gid(&self, gid: gid_t) -> Result<(), SyscallError> {
        self.calls.lock().unwrap().push(Call::SetGid(gid));
        self.setgid
    }

    fn set_uid(&self, uid: uid_t) -> Result<(), SyscallError> {
        self.calls.lock().unwrap().push(Call::SetUid(uid));
        self.setuid
    }

    fn inspect_credentials(&self, max_groups: usize) -> Result<ObservedCredentials, SyscallError> {
        self.calls.lock().unwrap().push(Call::Inspect(max_groups));
        self.observed.clone()
    }
}

fn credentials(groups: Vec<u32>) -> ResolvedUnixCredentials {
    ResolvedUnixCredentials {
        identity: UnixIdentity {
            username: "user".to_owned(),
            uid: 1000,
            gid: 1000,
            home: "/home/user".into(),
            shell: "/bin/sh".into(),
        },
        supplementary_gids: groups,
    }
}

fn observed(groups: Vec<gid_t>) -> ObservedCredentials {
    ObservedCredentials {
        real_uid: 1000,
        effective_uid: 1000,
        saved_uid: 1000,
        real_gid: 1000,
        effective_gid: 1000,
        saved_gid: 1000,
        supplementary_gids: groups,
    }
}

fn success(groups: Vec<gid_t>) -> RecordingSyscalls {
    RecordingSyscalls {
        calls: Mutex::new(Vec::new()),
        setgroups: Ok(()),
        setgid: Ok(()),
        setuid: Ok(()),
        observed: Ok(observed(groups)),
    }
}

#[test]
fn applies_credentials_in_required_order() {
    let syscalls = success(vec![1000, 30, 10, 20]);
    let result = drop_privileges_with(&syscalls, &credentials(vec![10, 20, 30]))
        .expect("drop should succeed");

    assert_eq!(result.uid, 1000);
    assert_eq!(
        *syscalls.calls.lock().unwrap(),
        vec![
            Call::SetGroups(vec![10, 20, 30]),
            Call::SetGid(1000),
            Call::SetUid(1000),
            Call::Inspect(4),
        ]
    );
}

#[test]
fn empty_groups_are_explicitly_cleared() {
    let syscalls = success(vec![1000]);
    drop_privileges_with(&syscalls, &credentials(vec![])).expect("drop should succeed");
    assert_eq!(syscalls.calls.lock().unwrap()[0], Call::SetGroups(vec![]));
}

#[test]
fn setter_failures_stop_the_sequence() {
    let cases = [
        (Err(SyscallError::Failed), Ok(()), Ok(()), 1),
        (Ok(()), Err(SyscallError::Failed), Ok(()), 2),
        (Ok(()), Ok(()), Err(SyscallError::Failed), 3),
    ];
    for (setgroups, setgid, setuid, call_count) in cases {
        let syscalls = RecordingSyscalls {
            calls: Mutex::new(Vec::new()),
            setgroups,
            setgid,
            setuid,
            observed: Ok(observed(vec![1000])),
        };
        assert!(drop_privileges_with(&syscalls, &credentials(vec![])).is_err());
        assert_eq!(syscalls.calls.lock().unwrap().len(), call_count);
    }
}

#[test]
fn mismatches_are_rejected_after_inspection() {
    let fields: [fn(&mut ObservedCredentials); 6] = [
        |value| value.real_uid = 1001,
        |value| value.effective_uid = 1001,
        |value| value.saved_uid = 1001,
        |value| value.real_gid = 1001,
        |value| value.effective_gid = 1001,
        |value| value.saved_gid = 1001,
    ];
    for mutate in fields {
        let mut mismatch = observed(vec![1000]);
        mutate(&mut mismatch);
        let syscalls = RecordingSyscalls {
            calls: Mutex::new(Vec::new()),
            setgroups: Ok(()),
            setgid: Ok(()),
            setuid: Ok(()),
            observed: Ok(mismatch),
        };
        assert_eq!(
            drop_privileges_with(&syscalls, &credentials(vec![])),
            Err(PrivilegeDropError::CredentialMismatch)
        );
    }
}

#[test]
fn supplementary_group_mismatch_is_rejected() {
    let syscalls = success(vec![1000, 10, 30]);
    assert_eq!(
        drop_privileges_with(&syscalls, &credentials(vec![10, 20])),
        Err(PrivilegeDropError::CredentialMismatch)
    );
}

#[test]
fn excessive_observed_group_count_is_credential_mismatch() {
    let syscalls = RecordingSyscalls {
        calls: Mutex::new(Vec::new()),
        setgroups: Ok(()),
        setgid: Ok(()),
        setuid: Ok(()),
        observed: Err(SyscallError::ObservedGroupCountExceeded),
    };
    assert_eq!(
        drop_privileges_with(&syscalls, &credentials(vec![10, 20])),
        Err(PrivilegeDropError::CredentialMismatch)
    );
}

#[test]
fn observed_group_limit_allows_primary_gid_entry() {
    assert_eq!(HARD_MAX_OBSERVED_GROUPS, 65_537);
    assert_eq!(
        bounded_max_observed_groups(HARD_MAX_SUPPLEMENTARY_GROUPS + 1),
        HARD_MAX_OBSERVED_GROUPS
    );
}

#[test]
fn primary_gid_in_observed_groups_is_ignored_for_comparison() {
    let syscalls = success(vec![20, 1000, 10, 10]);
    drop_privileges_with(&syscalls, &credentials(vec![10, 20]))
        .expect("primary group should be ignored");
}

#[test]
fn primary_gid_in_requested_groups_is_rejected_before_mutation() {
    let syscalls = success(vec![1000]);
    assert_eq!(
        drop_privileges_with(&syscalls, &credentials(vec![1000])),
        Err(PrivilegeDropError::InvalidSupplementaryGroups)
    );
    assert!(syscalls.calls.lock().unwrap().is_empty());
}
