use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use niralis_protocol::{NiralisRequest, NiralisResponse};
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::config::Config;
use crate::error::{NiralisdError, Result};
use crate::handler::RequestHandler;

const NSS_BUFFER_FALLBACK: usize = 1024;
const NSS_BUFFER_MAX: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GreeterIdentity {
    username: String,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

enum NssLookupResult {
    Found(GreeterIdentity),
    NotFound,
    Retry,
    Error(io::Error),
}

pub fn run<H>(config: &Config, handler: H) -> Result<()>
where
    H: RequestHandler + 'static,
{
    let greeter = resolve_greeter_identity(&config.greeter.user)?;
    let listener = bind_socket(&config.daemon.socket, &greeter)?;
    let handler = Arc::new(handler);

    info!(socket = %config.daemon.socket.display(), "niralisd listening");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let handler = Arc::clone(&handler);
                if let Err(error) = handle_client(stream, handler.as_ref()) {
                    warn!(%error, "failed to handle ipc client");
                }
            }
            Err(error) => warn!(%error, "failed to accept ipc client"),
        }
    }

    Ok(())
}

fn bind_socket(socket_path: &Path, greeter: &GreeterIdentity) -> Result<UnixListener> {
    bind_socket_with(socket_path, greeter, set_socket_ownership)
}

fn bind_socket_with<F>(
    socket_path: &Path,
    greeter: &GreeterIdentity,
    ownership_setter: F,
) -> Result<UnixListener>
where
    F: FnOnce(&Path, libc::uid_t, libc::gid_t) -> io::Result<()>,
{
    let runtime_dir = socket_path
        .parent()
        .ok_or_else(|| NiralisdError::InvalidSocketPath(socket_path.to_path_buf()))?;

    fs::create_dir_all(runtime_dir)?;
    fs::set_permissions(runtime_dir, fs::Permissions::from_mode(0o755))?;

    if socket_path.exists() {
        let metadata = fs::metadata(socket_path)?;
        if metadata.file_type().is_socket() {
            fs::remove_file(socket_path)?;
        } else {
            return Err(NiralisdError::InvalidSocketPath(socket_path.to_path_buf()));
        }
    }

    let listener = UnixListener::bind(socket_path)?;
    if let Err(error) = configure_socket(socket_path, greeter, ownership_setter) {
        drop(listener);
        let _ = fs::remove_file(socket_path);
        return Err(error);
    }

    Ok(listener)
}

fn configure_socket<F>(
    socket_path: &Path,
    greeter: &GreeterIdentity,
    ownership_setter: F,
) -> Result<()>
where
    F: FnOnce(&Path, libc::uid_t, libc::gid_t) -> io::Result<()>,
{
    // The service UMask creates the socket with no group or other access. Keep
    // that restrictive state while changing its group, then expose it exactly.
    ownership_setter(socket_path, 0, greeter.gid)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
    Ok(())
}

fn set_socket_ownership(socket_path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    let path = CString::new(socket_path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path contains a NUL byte",
        )
    })?;

    // SAFETY: `path` is a NUL-terminated copy that remains alive for this call.
    let result = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn resolve_greeter_identity(username: &str) -> Result<GreeterIdentity> {
    resolve_greeter_identity_with(username, lookup_passwd)
}

fn resolve_greeter_identity_with<F>(username: &str, mut lookup: F) -> Result<GreeterIdentity>
where
    F: FnMut(&CStr, &mut [libc::c_char]) -> NssLookupResult,
{
    let username_c =
        CString::new(username).map_err(|_| NiralisdError::GreeterUserNameContainsNul)?;
    let mut buffer = vec![0; nss_initial_buffer_size()];

    loop {
        match lookup(&username_c, &mut buffer) {
            NssLookupResult::Found(identity) => return validate_greeter_identity(identity),
            NssLookupResult::NotFound => {
                return Err(NiralisdError::GreeterUserNotFound(username.to_owned()));
            }
            NssLookupResult::Error(source) => {
                return Err(NiralisdError::GreeterIdentityLookupFailed {
                    username: username.to_owned(),
                    source,
                });
            }
            NssLookupResult::Retry => {
                let next_size = buffer
                    .len()
                    .checked_mul(2)
                    .filter(|size| *size <= NSS_BUFFER_MAX)
                    .ok_or_else(|| NiralisdError::GreeterIdentityLookupFailed {
                        username: username.to_owned(),
                        source: io::Error::from_raw_os_error(libc::ERANGE),
                    })?;
                buffer.resize(next_size, 0);
            }
        }
    }
}

fn validate_greeter_identity(identity: GreeterIdentity) -> Result<GreeterIdentity> {
    if identity.uid == 0 {
        return Err(NiralisdError::InvalidGreeterUid);
    }
    if identity.gid == 0 {
        return Err(NiralisdError::InvalidGreeterGid);
    }
    Ok(identity)
}

fn nss_initial_buffer_size() -> usize {
    // SAFETY: `sysconf` has no Rust-visible memory safety preconditions.
    let configured_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if configured_size > 0 {
        usize::try_from(configured_size)
            .ok()
            .filter(|size| *size <= NSS_BUFFER_MAX)
            .unwrap_or(NSS_BUFFER_FALLBACK)
    } else {
        NSS_BUFFER_FALLBACK
    }
}

fn lookup_passwd(username: &CStr, buffer: &mut [libc::c_char]) -> NssLookupResult {
    // SAFETY: all pointers reference valid writable storage for the duration of
    // this reentrant NSS call. The passwd fields are copied before returning.
    unsafe {
        let mut passwd: libc::passwd = std::mem::zeroed();
        let mut result = std::ptr::null_mut();
        let status = libc::getpwnam_r(
            username.as_ptr(),
            &mut passwd,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        );

        if status == libc::ERANGE {
            return NssLookupResult::Retry;
        }
        if status != 0 {
            return NssLookupResult::Error(io::Error::from_raw_os_error(status));
        }
        if result.is_null() {
            return NssLookupResult::NotFound;
        }

        let canonical_name = CStr::from_ptr(passwd.pw_name)
            .to_string_lossy()
            .into_owned();
        NssLookupResult::Found(GreeterIdentity {
            username: canonical_name,
            uid: passwd.pw_uid,
            gid: passwd.pw_gid,
        })
    }
}

fn handle_client<H>(stream: UnixStream, handler: &H) -> Result<()>
where
    H: RequestHandler,
{
    let writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut line = Zeroizing::new(String::new());

    reader.read_line(&mut *line)?;
    debug!("received ipc request");

    let response = if line.trim().is_empty() {
        NiralisResponse::Error {
            message: "empty request".to_owned(),
        }
    } else {
        let request: NiralisRequest = serde_json::from_str(line.trim_end())?;
        (*line).zeroize();
        handler.handle(request)
    };

    write_response(writer, &response)?;

    Ok(())
}

fn write_response(mut writer: UnixStream, response: &NiralisResponse) -> Result<()> {
    serde_json::to_writer(&mut writer, response)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn identity(uid: libc::uid_t, gid: libc::gid_t) -> GreeterIdentity {
        GreeterIdentity {
            username: "canonical-greeter".to_owned(),
            uid,
            gid,
        }
    }

    #[test]
    fn valid_greeter_resolves_to_the_identity_returned_by_nss() {
        let resolved = resolve_greeter_identity_with("configured-greeter", |_, _| {
            NssLookupResult::Found(identity(464, 465))
        })
        .unwrap();

        assert_eq!(resolved, identity(464, 465));
    }

    #[test]
    fn nonexistent_greeter_fails_closed() {
        let error =
            resolve_greeter_identity_with("missing", |_, _| NssLookupResult::NotFound).unwrap_err();

        assert!(matches!(error, NiralisdError::GreeterUserNotFound(name) if name == "missing"));
    }

    #[test]
    fn root_uid_is_rejected() {
        let error = resolve_greeter_identity_with("greeter", |_, _| {
            NssLookupResult::Found(identity(0, 464))
        })
        .unwrap_err();

        assert!(matches!(error, NiralisdError::InvalidGreeterUid));
    }

    #[test]
    fn root_primary_gid_is_rejected() {
        let error = resolve_greeter_identity_with("greeter", |_, _| {
            NssLookupResult::Found(identity(464, 0))
        })
        .unwrap_err();

        assert!(matches!(error, NiralisdError::InvalidGreeterGid));
    }

    #[test]
    fn nul_in_greeter_name_is_rejected_without_nss_lookup() {
        let error = resolve_greeter_identity_with("greeter\0injected", |_, _| {
            panic!("NSS lookup must not receive a name containing NUL")
        })
        .unwrap_err();

        assert!(matches!(error, NiralisdError::GreeterUserNameContainsNul));
    }

    #[test]
    fn nss_lookup_error_is_propagated() {
        let error = resolve_greeter_identity_with("greeter", |_, _| {
            NssLookupResult::Error(io::Error::from_raw_os_error(libc::EIO))
        })
        .unwrap_err();

        assert!(matches!(
            error,
            NiralisdError::GreeterIdentityLookupFailed { source, .. }
                if source.raw_os_error() == Some(libc::EIO)
        ));
    }

    #[test]
    fn erange_retries_with_a_larger_buffer() {
        let calls = RefCell::new(0);
        let resolved = resolve_greeter_identity_with("greeter", |_, buffer| {
            let mut calls = calls.borrow_mut();
            *calls += 1;
            if *calls == 1 {
                assert!(buffer.len() < NSS_BUFFER_MAX);
                NssLookupResult::Retry
            } else {
                NssLookupResult::Found(identity(464, 465))
            }
        })
        .unwrap();

        assert_eq!(resolved.gid, 465);
        assert_eq!(*calls.borrow(), 2);
    }

    #[test]
    fn socket_uses_greeter_primary_gid_and_mode_0660() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("niralisd.sock");
        let ownership = RefCell::new(None);
        let greeter = identity(464, 465);

        let listener = bind_socket_with(&socket_path, &greeter, |_, uid, gid| {
            *ownership.borrow_mut() = Some((uid, gid));
            Ok(())
        })
        .unwrap();

        let mode = fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        assert_eq!(*ownership.borrow(), Some((0, 465)));
        drop(listener);
    }

    #[test]
    fn ownership_failure_returns_no_listener_and_removes_socket() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("niralisd.sock");

        let error = bind_socket_with(&socket_path, &identity(464, 465), |_, _, _| {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })
        .unwrap_err();

        assert!(
            matches!(error, NiralisdError::Io(source) if source.raw_os_error() == Some(libc::EPERM))
        );
        assert!(!socket_path.exists());
    }
}
