use std::ffi::{CStr, CString};

use libloading::{Library, Symbol};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogindSessionId(String);

impl LogindSessionId {
    pub fn new(value: String) -> Result<Self, LogindError> {
        if value.is_empty() || value.len() > 128 || value.as_bytes().contains(&0) {
            return Err(LogindError::InvalidSessionId);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogindSessionIdentity {
    pub id: LogindSessionId,
    pub uid: u32,
    pub session_type: String,
    pub class: String,
    pub desktop: Option<String>,
    pub seat: Option<String>,
    pub vtnr: Option<u32>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum LogindError {
    #[error("logind is unavailable")]
    Unavailable,
    #[error("logind session id is invalid")]
    InvalidSessionId,
    #[error("{operation} failed with {result}")]
    QueryFailed {
        operation: &'static str,
        result: libc::c_int,
    },
}

pub trait LogindSessionResolver: Send + Sync {
    fn resolve_by_pid(&self, pid: u32) -> Result<Option<LogindSessionIdentity>, LogindError>;
    fn resolve_by_id(
        &self,
        id: &LogindSessionId,
    ) -> Result<Option<LogindSessionIdentity>, LogindError>;
}

#[derive(Debug, Default)]
pub struct SdLoginResolver;

impl LogindSessionResolver for SdLoginResolver {
    fn resolve_by_pid(&self, pid: u32) -> Result<Option<LogindSessionIdentity>, LogindError> {
        let library = load()?;
        unsafe {
            let function: Symbol<
                unsafe extern "C" fn(libc::pid_t, *mut *mut libc::c_char) -> libc::c_int,
            > = library
                .get(b"sd_pid_get_session\0")
                .map_err(|_| LogindError::Unavailable)?;
            let mut value = std::ptr::null_mut();
            let result = function(pid as libc::pid_t, &mut value);
            if pid_has_no_logind_session(result) {
                return Ok(None);
            }
            if result < 0 || value.is_null() {
                return Err(LogindError::QueryFailed {
                    operation: "sd_pid_get_session",
                    result,
                });
            }
            let id = CStr::from_ptr(value)
                .to_str()
                .map_err(|_| LogindError::InvalidSessionId)?
                .to_owned();
            libc::free(value.cast());
            self.resolve_by_id(&LogindSessionId::new(id)?)
        }
    }

    fn resolve_by_id(
        &self,
        id: &LogindSessionId,
    ) -> Result<Option<LogindSessionIdentity>, LogindError> {
        let library = load()?;
        unsafe {
            let uid: Symbol<
                unsafe extern "C" fn(*const libc::c_char, *mut libc::uid_t) -> libc::c_int,
            > = library
                .get(b"sd_session_get_uid\0")
                .map_err(|_| LogindError::Unavailable)?;
            let ty: Symbol<
                unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char) -> libc::c_int,
            > = library
                .get(b"sd_session_get_type\0")
                .map_err(|_| LogindError::Unavailable)?;
            let class: Symbol<
                unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char) -> libc::c_int,
            > = library
                .get(b"sd_session_get_class\0")
                .map_err(|_| LogindError::Unavailable)?;
            let desktop: Symbol<
                unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char) -> libc::c_int,
            > = library
                .get(b"sd_session_get_desktop\0")
                .map_err(|_| LogindError::Unavailable)?;
            let seat: Symbol<
                unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char) -> libc::c_int,
            > = library
                .get(b"sd_session_get_seat\0")
                .map_err(|_| LogindError::Unavailable)?;
            let vt: Symbol<
                unsafe extern "C" fn(*const libc::c_char, *mut libc::c_uint) -> libc::c_int,
            > = library
                .get(b"sd_session_get_vt\0")
                .map_err(|_| LogindError::Unavailable)?;
            let id_c = CString::new(id.as_str()).map_err(|_| LogindError::InvalidSessionId)?;
            let mut value_uid = 0;
            if uid(id_c.as_ptr(), &mut value_uid) < 0 {
                return Ok(None);
            }
            Ok(Some(LogindSessionIdentity {
                id: id.clone(),
                uid: value_uid,
                session_type: string_value("sd_session_get_type", ty, id_c.as_ptr())?,
                class: string_value("sd_session_get_class", class, id_c.as_ptr())?,
                desktop: string_value("sd_session_get_desktop", desktop, id_c.as_ptr()).ok(),
                seat: optional_string_value("sd_session_get_seat", seat, id_c.as_ptr()),
                vtnr: optional_vtnr(vt, id_c.as_ptr()),
            }))
        }
    }
}

fn pid_has_no_logind_session(result: libc::c_int) -> bool {
    // sd_pid_get_session() reports a PID outside a logind session as ENODATA
    // on current systemd releases. Older implementations may return ENXIO;
    // ENOENT remains useful for a PID whose proc entry disappeared mid-query.
    result == -libc::ENODATA || result == -libc::ENXIO || result == -libc::ENOENT
}

fn load() -> Result<Library, LogindError> {
    unsafe { Library::new("libsystemd.so.0").map_err(|_| LogindError::Unavailable) }
}
unsafe fn string_value(
    operation: &'static str,
    function: Symbol<
        unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char) -> libc::c_int,
    >,
    id: *const libc::c_char,
) -> Result<String, LogindError> {
    let mut value = std::ptr::null_mut();
    let status = function(id, &mut value);
    if status < 0 || value.is_null() {
        return Err(LogindError::QueryFailed {
            operation,
            result: status,
        });
    }
    let result = CStr::from_ptr(value)
        .to_str()
        .map_err(|_| LogindError::QueryFailed {
            operation,
            result: status,
        })?
        .to_owned();
    libc::free(value.cast());
    Ok(result)
}

unsafe fn optional_string_value(
    operation: &'static str,
    function: Symbol<
        unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char) -> libc::c_int,
    >,
    id: *const libc::c_char,
) -> Option<String> {
    string_value(operation, function, id).ok()
}

unsafe fn optional_vtnr(
    function: Symbol<unsafe extern "C" fn(*const libc::c_char, *mut libc::c_uint) -> libc::c_int>,
    id: *const libc::c_char,
) -> Option<u32> {
    let mut value = 0;
    if function(id, &mut value) < 0 || value == 0 {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::pid_has_no_logind_session;

    #[test]
    fn recognizes_systemd_no_session_results() {
        assert!(pid_has_no_logind_session(-libc::ENODATA));
        assert!(pid_has_no_logind_session(-libc::ENXIO));
        assert!(pid_has_no_logind_session(-libc::ENOENT));
        assert!(!pid_has_no_logind_session(-libc::EACCES));
    }
}
