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
