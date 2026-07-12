use std::ffi::{CStr, CString};

use libloading::Library;
use serde::{Deserialize, Serialize};

const MAX_SELINUX_CONTEXT_BYTES: usize = 4096;

/// A context obtained from pam_selinux's pending exec context. It is deliberately
/// opaque: callers may compare or apply it, but normal Debug output is redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PamSelinuxExecContext(String);

impl std::fmt::Debug for PamSelinuxExecContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PamSelinuxExecContext([redacted])")
    }
}

impl PamSelinuxExecContext {
    pub(crate) fn new(value: String) -> Result<Self, SelinuxError> {
        if value.is_empty()
            || value.len() > MAX_SELINUX_CONTEXT_BYTES
            || value.as_bytes().contains(&0)
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(SelinuxError::InvalidContext);
        }
        // SELinux contexts have user:role:type:range shape, but an MLS/MCS
        // range itself may contain colons (for example s0-s0:c0.c1023).
        // Validate the fixed prefix and keep the range opaque.
        let mut fields = value.splitn(4, ':');
        if fields.by_ref().take(4).count() != 4 || fields.any(str::is_empty) {
            return Err(SelinuxError::InvalidContext);
        }
        Ok(Self(value))
    }

    pub(crate) fn matches(&self, observed: &PamSelinuxExecContext) -> bool {
        self.0 == observed.0
    }

    fn as_c_str(&self) -> Result<CString, SelinuxError> {
        CString::new(self.0.as_bytes()).map_err(|_| SelinuxError::InvalidContext)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelinuxError {
    Unavailable,
    QueryFailed,
    PendingContextMissing,
    InvalidContext,
    ClearFailed,
    ApplyFailed,
}

pub trait SelinuxContextManager: Send + Sync {
    /// `None` means SELinux is disabled. If enabled, a pending context is
    /// mandatory after pam_selinux has opened the session.
    fn capture_pending(&self) -> Result<Option<PamSelinuxExecContext>, SelinuxError>;
    fn clear_pending(&self) -> Result<(), SelinuxError>;
    fn apply_pending(&self, context: &PamSelinuxExecContext) -> Result<(), SelinuxError>;
    fn context_for_pid(&self, pid: u32) -> Result<PamSelinuxExecContext, SelinuxError>;
}

#[derive(Debug, Default)]
pub struct LinuxSelinuxContextManager;

impl SelinuxContextManager for LinuxSelinuxContextManager {
    fn capture_pending(&self) -> Result<Option<PamSelinuxExecContext>, SelinuxError> {
        let library = load()?;
        unsafe {
            if !enabled(&library)? {
                return Ok(None);
            }
            let getexeccon = library
                .get::<unsafe extern "C" fn(*mut *mut libc::c_char) -> libc::c_int>(b"getexeccon\0")
                .map_err(|_| SelinuxError::Unavailable)?;
            read_context(*getexeccon)?
                .map(PamSelinuxExecContext::new)
                .transpose()?
                .ok_or(SelinuxError::PendingContextMissing)
                .map(Some)
        }
    }

    fn clear_pending(&self) -> Result<(), SelinuxError> {
        let library = load()?;
        unsafe {
            if !enabled(&library)? {
                return Ok(());
            }
            let setexeccon = library
                .get::<unsafe extern "C" fn(*const libc::c_char) -> libc::c_int>(b"setexeccon\0")
                .map_err(|_| SelinuxError::Unavailable)?;
            if setexeccon(std::ptr::null()) < 0 {
                return Err(SelinuxError::ClearFailed);
            }
            Ok(())
        }
    }

    fn apply_pending(&self, context: &PamSelinuxExecContext) -> Result<(), SelinuxError> {
        let library = load()?;
        unsafe {
            let setexeccon = library
                .get::<unsafe extern "C" fn(*const libc::c_char) -> libc::c_int>(b"setexeccon\0")
                .map_err(|_| SelinuxError::Unavailable)?;
            let context = context.as_c_str()?;
            if setexeccon(context.as_ptr()) < 0 {
                return Err(SelinuxError::ApplyFailed);
            }
            Ok(())
        }
    }

    fn context_for_pid(&self, pid: u32) -> Result<PamSelinuxExecContext, SelinuxError> {
        let library = load()?;
        unsafe {
            if !enabled(&library)? {
                return Err(SelinuxError::QueryFailed);
            }
            let getpidcon = library
                .get::<unsafe extern "C" fn(libc::pid_t, *mut *mut libc::c_char) -> libc::c_int>(
                    b"getpidcon\0",
                )
                .map_err(|_| SelinuxError::Unavailable)?;
            read_context_with_pid(*getpidcon, pid)?
                .map(PamSelinuxExecContext::new)
                .transpose()?
                .ok_or(SelinuxError::QueryFailed)
        }
    }
}

fn load() -> Result<Library, SelinuxError> {
    unsafe { Library::new("libselinux.so.1").map_err(|_| SelinuxError::Unavailable) }
}

unsafe fn enabled(library: &Library) -> Result<bool, SelinuxError> {
    let function = library
        .get::<unsafe extern "C" fn() -> libc::c_int>(b"is_selinux_enabled\0")
        .map_err(|_| SelinuxError::Unavailable)?;
    match function() {
        value if value > 0 => Ok(true),
        0 => Ok(false),
        _ => Err(SelinuxError::QueryFailed),
    }
}

unsafe fn read_context(
    query: unsafe extern "C" fn(*mut *mut libc::c_char) -> libc::c_int,
) -> Result<Option<String>, SelinuxError> {
    let mut value = std::ptr::null_mut();
    if query(&mut value) < 0 {
        return Err(SelinuxError::QueryFailed);
    }
    if value.is_null() {
        return Ok(None);
    }
    let context = CStr::from_ptr(value)
        .to_str()
        .map_err(|_| SelinuxError::InvalidContext)?
        .to_owned();
    libc::free(value.cast());
    Ok(Some(context))
}

unsafe fn read_context_with_pid(
    query: unsafe extern "C" fn(libc::pid_t, *mut *mut libc::c_char) -> libc::c_int,
    pid: u32,
) -> Result<Option<String>, SelinuxError> {
    let mut value = std::ptr::null_mut();
    if query(pid as libc::pid_t, &mut value) < 0 {
        return Err(SelinuxError::QueryFailed);
    }
    if value.is_null() {
        return Ok(None);
    }
    let context = CStr::from_ptr(value)
        .to_str()
        .map_err(|_| SelinuxError::InvalidContext)?
        .to_owned();
    libc::free(value.cast());
    Ok(Some(context))
}

#[cfg(test)]
mod tests {
    use super::{PamSelinuxExecContext, SelinuxError};

    #[test]
    fn accepts_a_basic_pam_selinux_context() {
        assert!(
            PamSelinuxExecContext::new("unconfined_u:unconfined_r:unconfined_t:s0".to_owned())
                .is_ok()
        );
    }

    #[test]
    fn accepts_a_pam_selinux_context_with_an_mls_range() {
        assert!(PamSelinuxExecContext::new(
            "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023".to_owned()
        )
        .is_ok());
    }

    #[test]
    fn rejects_missing_fields_nul_and_oversized_contexts() {
        for value in [
            "unconfined_u:unconfined_r:unconfined_t".to_owned(),
            "unconfined_u:unconfined_r:unconfined_t:s0\0bad".to_owned(),
            "a".repeat(4097),
        ] {
            assert_eq!(
                PamSelinuxExecContext::new(value),
                Err(SelinuxError::InvalidContext)
            );
        }
    }
}
