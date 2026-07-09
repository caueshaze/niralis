use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStringExt;

use libc::{c_char, passwd, _SC_GETPW_R_SIZE_MAX, ERANGE};

use super::{IdentityError, UnixIdentity, UnixIdentityResolver};

const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;
const MAX_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Debug, Default, Clone, Copy)]
pub struct NssUnixIdentityResolver;

impl UnixIdentityResolver for NssUnixIdentityResolver {
    fn resolve(&self, username: &str) -> Result<UnixIdentity, IdentityError> {
        lookup_user_with(username, &LibcPasswdLookup)
    }
}

pub(crate) trait PasswdLookup {
    fn initial_buffer_size(&self) -> usize;

    fn lookup(&self, username: &CString, passwd: &mut passwd, buffer: &mut [u8]) -> LookupResult;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LookupResult {
    Success,
    NotFound,
    Range,
    Failure,
}

struct LibcPasswdLookup;

impl PasswdLookup for LibcPasswdLookup {
    fn initial_buffer_size(&self) -> usize {
        initial_buffer_size()
    }

    fn lookup(&self, username: &CString, passwd: &mut passwd, buffer: &mut [u8]) -> LookupResult {
        let mut result = std::ptr::null_mut();
        let code = unsafe {
            libc::getpwnam_r(
                username.as_ptr(),
                passwd,
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len(),
                &mut result,
            )
        };

        match (code, result.is_null()) {
            (0, false) => LookupResult::Success,
            (0, true) => LookupResult::NotFound,
            (ERANGE, _) => LookupResult::Range,
            _ => LookupResult::Failure,
        }
    }
}

pub(crate) fn lookup_user_with<L: PasswdLookup>(
    username: &str,
    lookup: &L,
) -> Result<UnixIdentity, IdentityError> {
    let username = CString::new(username).map_err(|_| IdentityError::InvalidUsername)?;
    let mut buffer_size = lookup.initial_buffer_size().min(MAX_BUFFER_SIZE);

    loop {
        let mut record = zeroed_passwd();
        let mut buffer = vec![0_u8; buffer_size];
        match lookup.lookup(&username, &mut record, &mut buffer) {
            LookupResult::Success => return passwd_to_identity(&record),
            LookupResult::NotFound => return Err(IdentityError::NotFound),
            LookupResult::Failure => return Err(IdentityError::LookupFailed),
            LookupResult::Range => {
                if buffer_size >= MAX_BUFFER_SIZE {
                    return Err(IdentityError::BufferLimitExceeded);
                }
                buffer_size = (buffer_size.saturating_mul(2)).min(MAX_BUFFER_SIZE);
            }
        }
    }
}

fn initial_buffer_size() -> usize {
    let raw = unsafe { libc::sysconf(_SC_GETPW_R_SIZE_MAX) };
    if raw > 0 {
        usize::try_from(raw).unwrap_or(DEFAULT_BUFFER_SIZE)
    } else {
        DEFAULT_BUFFER_SIZE
    }
}

fn passwd_to_identity(record: &passwd) -> Result<UnixIdentity, IdentityError> {
    let username = bytes_from_ptr(record.pw_name)
        .ok_or(IdentityError::InvalidCanonicalUsername)
        .and_then(|bytes| {
            if bytes.is_empty() {
                return Err(IdentityError::InvalidCanonicalUsername);
            }
            String::from_utf8(bytes).map_err(|_| IdentityError::InvalidCanonicalUsername)
        })?;

    Ok(UnixIdentity {
        username,
        uid: record.pw_uid,
        gid: record.pw_gid,
        home: OsString::from_vec(bytes_from_ptr(record.pw_dir).unwrap_or_default()).into(),
        shell: OsString::from_vec(bytes_from_ptr(record.pw_shell).unwrap_or_default()).into(),
    })
}

fn bytes_from_ptr(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return Some(Vec::new());
    }

    Some(unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec())
}

fn zeroed_passwd() -> passwd {
    unsafe { std::mem::zeroed() }
}
