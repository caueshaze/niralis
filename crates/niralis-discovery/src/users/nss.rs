use std::ffi::CStr;
use std::os::raw::c_char;

use crate::users::filter::SystemUser;
use crate::DiscoveryError;

pub(super) fn enumerate_system_users() -> Result<Vec<SystemUser>, DiscoveryError> {
    let _guard = PasswordDatabaseGuard::new();
    let mut users = Vec::new();

    loop {
        let entry = unsafe { libc::getpwent() };
        if entry.is_null() {
            break;
        }

        let user = unsafe {
            let entry = &*entry;
            SystemUser {
                uid: entry.pw_uid,
                username: c_string_lossy(entry.pw_name),
                gecos: c_string_lossy(entry.pw_gecos),
                shell: c_string_lossy(entry.pw_shell),
            }
        };

        if !user.username.is_empty() {
            users.push(user);
        }
    }

    Ok(users)
}

struct PasswordDatabaseGuard;

impl PasswordDatabaseGuard {
    fn new() -> Self {
        unsafe {
            libc::setpwent();
        }
        Self
    }
}

impl Drop for PasswordDatabaseGuard {
    fn drop(&mut self) {
        unsafe {
            libc::endpwent();
        }
    }
}

unsafe fn c_string_lossy(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}
