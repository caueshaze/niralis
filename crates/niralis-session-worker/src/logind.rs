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
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum LogindError {
    #[error("logind is unavailable")]
    Unavailable,
    #[error("logind session id is invalid")]
    InvalidSessionId,
    #[error("logind query failed")]
    QueryFailed,
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
            if result == -libc::ENXIO || result == -libc::ENOENT {
                return Ok(None);
            }
            if result < 0 || value.is_null() {
                return Err(LogindError::QueryFailed);
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
            let id_c = CString::new(id.as_str()).map_err(|_| LogindError::InvalidSessionId)?;
            let mut value_uid = 0;
            if uid(id_c.as_ptr(), &mut value_uid) < 0 {
                return Ok(None);
            }
            Ok(Some(LogindSessionIdentity {
                id: id.clone(),
                uid: value_uid,
                session_type: string_value(ty, id_c.as_ptr())?,
                class: string_value(class, id_c.as_ptr())?,
                desktop: string_value(desktop, id_c.as_ptr()).ok(),
            }))
        }
    }
}

fn load() -> Result<Library, LogindError> {
    unsafe { Library::new("libsystemd.so.0").map_err(|_| LogindError::Unavailable) }
}
unsafe fn string_value(
    function: Symbol<
        unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char) -> libc::c_int,
    >,
    id: *const libc::c_char,
) -> Result<String, LogindError> {
    let mut value = std::ptr::null_mut();
    if function(id, &mut value) < 0 || value.is_null() {
        return Err(LogindError::QueryFailed);
    }
    let result = CStr::from_ptr(value)
        .to_str()
        .map_err(|_| LogindError::QueryFailed)?
        .to_owned();
    libc::free(value.cast());
    Ok(result)
}
