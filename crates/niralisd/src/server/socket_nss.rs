use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use niralis_protocol::{
    GreeterHandshake, GreeterHandshakeResponse, GreeterRequest,
    GreeterRequestEnvelope, GreeterResponseEnvelope, NiralisRequest,
    GREETER_PROTOCOL_VERSION, MAX_GREETER_FRAME_BYTES,
};
use tracing::{info, warn};
use crate::config::Config;
use crate::connection::GreeterConnectionAuthority;
use crate::error::{NiralisdError, Result};
use crate::handler::{RecoveryAdminHandler, RequestHandler};
const NSS_BUFFER_FALLBACK: usize = 1024;
const NSS_BUFFER_MAX: usize = 1024 * 1024;
const MAX_GREETER_CONNECTIONS: usize = 32;
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
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
    H: RequestHandler + RecoveryAdminHandler + 'static,
{
    let greeter = resolve_greeter_identity(&config.greeter.user)?;
    let listener = bind_socket(&config.daemon.socket, &greeter)?;
    let handler = Arc::new(handler);

    recovery_admin::start(Arc::clone(&handler))?;

    info!(socket = %config.daemon.socket.display(), "niralisd listening");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if ACTIVE_CONNECTIONS.fetch_add(1, Ordering::AcqRel) >= MAX_GREETER_CONNECTIONS {
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
                    warn!("greeter connection limit reached");
                    continue;
                }
                let handler = Arc::clone(&handler);
                let expected_peer = greeter.clone();
                let seat = config.daemon.seat.clone();
                std::thread::spawn(move || {
                    let result = handle_client(stream, handler.as_ref(), &expected_peer, &seat);
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
                    if let Err(error) = result {
                        warn!(%error, "failed to handle ipc client");
                    }
                });
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
    F: FnOnce(RawFd, libc::uid_t, libc::gid_t) -> io::Result<()>,
{
    let runtime_dir = socket_path
        .parent()
        .ok_or_else(|| NiralisdError::InvalidSocketPath(socket_path.to_path_buf()))?;

    if runtime_dir.exists() {
        let metadata = fs::symlink_metadata(runtime_dir)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(NiralisdError::InvalidSocketPath(runtime_dir.to_path_buf()));
        }
    } else {
        fs::create_dir_all(runtime_dir)?;
    }
    secure_runtime_dir(runtime_dir)?;

    if let Ok(metadata) = fs::symlink_metadata(socket_path) {
        if metadata.file_type().is_symlink() {
            return Err(NiralisdError::InvalidSocketPath(socket_path.to_path_buf()));
        }
        if metadata.file_type().is_socket() {
            fs::remove_file(socket_path)?;
        } else {
            return Err(NiralisdError::InvalidSocketPath(socket_path.to_path_buf()));
        }
    }

    let listener = UnixListener::bind(socket_path)?;
    if let Err(error) = configure_socket(
        listener.as_raw_fd(),
        socket_path,
        greeter,
        ownership_setter,
    ) {
        drop(listener);
        let _ = fs::remove_file(socket_path);
        return Err(error);
    }

    Ok(listener)
}

fn secure_runtime_dir(runtime_dir: &Path) -> Result<()> {
    let path = CString::new(runtime_dir.as_os_str().as_bytes())
        .map_err(|_| NiralisdError::InvalidSocketPath(runtime_dir.to_path_buf()))?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let raw = unsafe { libc::open(path.as_ptr(), flags) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: raw is a newly opened directory descriptor owned by this scope.
    let directory = unsafe { OwnedFd::from_raw_fd(raw) };
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn configure_socket<F>(
    socket_fd: RawFd,
    socket_path: &Path,
    greeter: &GreeterIdentity,
    ownership_setter: F,
) -> Result<()>
where
    F: FnOnce(RawFd, libc::uid_t, libc::gid_t) -> io::Result<()>,
{
    // The service UMask creates the socket with no group or other access. Keep
    // that restrictive state while changing its group, then expose it exactly.
    ownership_setter(socket_fd, 0, greeter.gid)?;
    let status = unsafe { libc::fchmod(socket_fd, 0o660) };
    if status != 0 {
        return Err(io::Error::last_os_error().into());
    }

    // Linux does not consistently expose permission changes made through an
    // AF_UNIX socket descriptor on the directory entry returned by
    // `metadata`. Apply the same explicit mode to the bound pathname as well;
    // the runtime directory is daemon-owned and mode 0700, so an unrelated
    // peer cannot replace the entry between bind and this operation.
    let metadata = fs::symlink_metadata(socket_path)?;
    if !metadata.file_type().is_socket() {
        return Err(NiralisdError::InvalidSocketPath(socket_path.to_path_buf()));
    }
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
    let mode = fs::symlink_metadata(socket_path)?.permissions().mode() & 0o777;
    if mode != 0o660 {
        return Err(NiralisdError::InvalidSocketPath(socket_path.to_path_buf()));
    }
    Ok(())
}

fn set_socket_ownership(socket_fd: RawFd, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    let result = unsafe { libc::fchown(socket_fd, uid, gid) };
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
