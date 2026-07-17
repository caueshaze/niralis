use std::cell::Cell;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

use libc::passwd;

use super::groups::{resolve_groups_with, GroupListLookup, GroupLookupResult};
use super::nss::{lookup_user_with, LookupResult, PasswdLookup};
use super::{
    GroupResolutionError, IdentityError, NssSupplementaryGroupsResolver, NssUnixIdentityResolver,
    SupplementaryGroupsResolver, UnixIdentity, UnixIdentityResolver,
};

struct StubLookup {
    calls: Cell<usize>,
    responses: Vec<LookupResult>,
    record: passwd,
}

impl PasswdLookup for StubLookup {
    fn initial_buffer_size(&self) -> usize {
        8
    }

    fn lookup(&self, _username: &CString, passwd: &mut passwd, _buffer: &mut [u8]) -> LookupResult {
        *passwd = self.record;
        let call = self.calls.get();
        self.calls.set(call + 1);
        self.responses
            .get(call)
            .copied()
            .unwrap_or(LookupResult::Failure)
    }
}

fn passwd_record(name: &CString, uid: u32, gid: u32, home: &CString, shell: &CString) -> passwd {
    passwd {
        pw_name: name.as_ptr().cast_mut(),
        pw_passwd: std::ptr::null_mut(),
        pw_uid: uid,
        pw_gid: gid,
        pw_gecos: std::ptr::null_mut(),
        pw_dir: home.as_ptr().cast_mut(),
        pw_shell: shell.as_ptr().cast_mut(),
    }
}

#[test]
fn rejects_username_with_nul() {
    let resolver = NssUnixIdentityResolver;

    let error = resolver.resolve("bad\0user").expect_err("NUL should fail");

    assert_eq!(error, IdentityError::InvalidUsername);
}

#[test]
fn resolves_identity_and_preserves_unix_path_bytes() {
    let name = CString::new("caue").expect("name");
    let home = CString::new(vec![b'/', b'h', b'o', b'm', b'e', b'/', 0xFF]).expect("home");
    let shell = CString::new(vec![b'/', b'b', b'i', b'n', b'/', 0xFE]).expect("shell");
    let lookup = StubLookup {
        calls: Cell::new(0),
        responses: vec![LookupResult::Success],
        record: passwd_record(&name, 1000, 1001, &home, &shell),
    };

    let identity = lookup_user_with("alias", &lookup).expect("identity should resolve");

    assert_eq!(identity.username, "caue");
    assert_eq!(identity.uid, 1000);
    assert_eq!(identity.gid, 1001);
    assert_eq!(identity.home.as_os_str().as_bytes(), b"/home/\xFF");
    assert_eq!(identity.shell.as_os_str().as_bytes(), b"/bin/\xFE");
}

#[test]
fn returns_not_found_for_missing_user() {
    let name = CString::new("unused").expect("name");
    let empty = CString::new("").expect("empty");
    let lookup = StubLookup {
        calls: Cell::new(0),
        responses: vec![LookupResult::NotFound],
        record: passwd_record(&name, 0, 0, &empty, &empty),
    };

    let error = lookup_user_with("ghost", &lookup).expect_err("missing user should fail");

    assert_eq!(error, IdentityError::NotFound);
}

#[test]
fn rejects_invalid_utf8_canonical_username() {
    let name = CString::new(vec![0xFF]).expect("name");
    let empty = CString::new("").expect("empty");
    let lookup = StubLookup {
        calls: Cell::new(0),
        responses: vec![LookupResult::Success],
        record: passwd_record(&name, 1000, 1000, &empty, &empty),
    };

    let error = lookup_user_with("alias", &lookup).expect_err("invalid username should fail");

    assert_eq!(error, IdentityError::InvalidCanonicalUsername);
}

#[test]
fn retries_after_erange() {
    let name = CString::new("caue").expect("name");
    let empty = CString::new("").expect("empty");
    let lookup = StubLookup {
        calls: Cell::new(0),
        responses: vec![LookupResult::Range, LookupResult::Success],
        record: passwd_record(&name, 1000, 1000, &empty, &empty),
    };

    let identity = lookup_user_with("caue", &lookup).expect("retry should succeed");

    assert_eq!(identity.username, "caue");
    assert_eq!(lookup.calls.get(), 2);
}

#[test]
fn fails_when_buffer_limit_is_exceeded() {
    let name = CString::new("caue").expect("name");
    let empty = CString::new("").expect("empty");
    let lookup = StubLookup {
        calls: Cell::new(0),
        responses: vec![
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
            LookupResult::Range,
        ],
        record: passwd_record(&name, 1000, 1000, &empty, &empty),
    };

    let error = lookup_user_with("caue", &lookup).expect_err("buffer growth should stop");

    assert_eq!(error, IdentityError::BufferLimitExceeded);
}

#[test]
fn classifies_getgrouplist_results() {
    use super::groups::classify_getgrouplist_result;

    assert_eq!(classify_getgrouplist_result(0), GroupLookupResult::Success);
    assert_eq!(classify_getgrouplist_result(1), GroupLookupResult::Success);
    assert_eq!(classify_getgrouplist_result(5), GroupLookupResult::Success);
    assert_eq!(
        classify_getgrouplist_result(libc::c_int::MAX),
        GroupLookupResult::Success
    );
    assert_eq!(
        classify_getgrouplist_result(-1),
        GroupLookupResult::BufferTooSmall
    );
    assert_eq!(classify_getgrouplist_result(-2), GroupLookupResult::Failure);
}

struct GroupStub {
    calls: Cell<usize>,
    responses: Vec<(GroupLookupResult, libc::c_int, Vec<libc::gid_t>)>,
    username: Cell<Option<String>>,
    primary_gid: Cell<Option<libc::gid_t>>,
}

impl GroupListLookup for GroupStub {
    fn lookup(
        &self,
        username: &CString,
        primary_gid: libc::gid_t,
        groups: &mut [libc::gid_t],
        ngroups: &mut libc::c_int,
    ) -> GroupLookupResult {
        self.username
            .set(Some(username.to_string_lossy().into_owned()));
        self.primary_gid.set(Some(primary_gid));
        let call = self.calls.get();
        self.calls.set(call + 1);
        let (result, count, values) = self.responses.get(call).expect("stub response");
        *ngroups = *count;
        groups[..values.len()].copy_from_slice(values);
        *result
    }
}

fn group_identity(username: &str, gid: u32) -> UnixIdentity {
    UnixIdentity {
        username: username.to_owned(),
        uid: 1000,
        gid,
        home: "/home/user".into(),
        shell: "/bin/sh".into(),
    }
}
