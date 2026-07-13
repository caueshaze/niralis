use libloading::{Library, Symbol};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum UserBusError {
    #[error("libsystemd user bus API unavailable")]
    Unavailable,
    #[error("user bus connection failed")]
    ConnectionFailed,
}

/// Opens the existing systemd user bus and asks libsystemd for its unique name.
/// This deliberately does not create or launch any bus daemon.
pub fn prove_user_bus() -> Result<(), UserBusError> {
    unsafe {
        let library = Library::new("libsystemd.so.0").map_err(|_| UserBusError::Unavailable)?;
        let open: Symbol<unsafe extern "C" fn(*mut *mut libc::c_void) -> libc::c_int> = library
            .get(b"sd_bus_open_user\0")
            .map_err(|_| UserBusError::Unavailable)?;
        let unique: Symbol<
            unsafe extern "C" fn(*mut libc::c_void, *mut *const libc::c_char) -> libc::c_int,
        > = library
            .get(b"sd_bus_get_unique_name\0")
            .map_err(|_| UserBusError::Unavailable)?;
        let unref: Symbol<unsafe extern "C" fn(*mut libc::c_void) -> *mut libc::c_void> = library
            .get(b"sd_bus_unref\0")
            .map_err(|_| UserBusError::Unavailable)?;
        let mut bus = std::ptr::null_mut();
        if open(&mut bus) < 0 || bus.is_null() {
            return Err(UserBusError::ConnectionFailed);
        }
        let mut name = std::ptr::null();
        let result = unique(bus, &mut name);
        let valid = result >= 0 && !name.is_null() && !CStr::from_ptr(name).to_bytes().is_empty();
        let _ = unref(bus);
        if valid {
            Ok(())
        } else {
            Err(UserBusError::ConnectionFailed)
        }
    }
}

use std::ffi::CStr;
