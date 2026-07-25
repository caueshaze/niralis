use std::fs;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use niralis_session::{
    RecoveryAdminEnvelope, RecoveryAdminRequest, RecoveryAdminResponse,
    MAX_RECOVERY_ADMIN_PACKET_BYTES, RECOVERY_ADMIN_PROTOCOL_VERSION,
};
use tracing::{info, warn};

use crate::error::{NiralisdError, Result};
use crate::handler::RecoveryAdminHandler;

const ADMIN_DIR: &str = "/run/niralis/recovery-admin";
const ADMIN_SOCKET: &str = "/run/niralis/recovery-admin/recovery.sock";

pub(super) fn start<H>(handler: Arc<H>) -> Result<()>
where
    H: RecoveryAdminHandler + 'static,
{
    let listener = bind_admin_socket()?;
    std::thread::Builder::new()
        .name("niralis-recovery-admin".to_owned())
        .spawn(move || serve(listener, handler))
        .map_err(NiralisdError::Io)?;
    info!(
        socket = ADMIN_SOCKET,
        "niralis recovery administration listening"
    );
    Ok(())
}

fn serve<H>(listener: OwnedFd, handler: Arc<H>)
where
    H: RecoveryAdminHandler,
{
    loop {
        let accepted = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if accepted < 0 {
            warn!(error = %io::Error::last_os_error(), "recovery administration accept failed");
            continue;
        }
        // SAFETY: accept4 returned a fresh file descriptor.
        let connection = unsafe { OwnedFd::from_raw_fd(accepted) };
        if let Err(error) = handle_connection(&connection, handler.as_ref()) {
            warn!(%error, "recovery administration request rejected");
        }
    }
}

fn handle_connection<H>(connection: &OwnedFd, handler: &H) -> io::Result<()>
where
    H: RecoveryAdminHandler,
{
    let peer = peer_credentials(connection)?;
    if peer.uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "recovery administration requires uid 0",
        ));
    }
    let mut buffer = vec![0_u8; MAX_RECOVERY_ADMIN_PACKET_BYTES];
    let received = unsafe {
        libc::recv(
            connection.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_TRUNC,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let received = usize::try_from(received)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative packet length"))?;
    if received == 0 || received > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid recovery administration packet size",
        ));
    }
    let response = match serde_json::from_slice::<RecoveryAdminEnvelope<RecoveryAdminRequest>>(
        &buffer[..received],
    ) {
        Ok(envelope) if envelope.version == RECOVERY_ADMIN_PROTOCOL_VERSION => {
            match handler.handle_recovery_admin(envelope.message) {
                Ok(message) => message,
                Err(reason) => RecoveryAdminResponse::Rejected {
                    reason,
                    sequence: None,
                },
            }
        }
        Ok(_) => RecoveryAdminResponse::Rejected {
            reason: "unsupported recovery administration protocol version".to_owned(),
            sequence: None,
        },
        Err(_) => RecoveryAdminResponse::Rejected {
            reason: "invalid recovery administration request".to_owned(),
            sequence: None,
        },
    };
    let encoded = serde_json::to_vec(&RecoveryAdminEnvelope {
        version: RECOVERY_ADMIN_PROTOCOL_VERSION,
        message: response,
    })
    .map_err(io::Error::other)?;
    if encoded.len() > MAX_RECOVERY_ADMIN_PACKET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery administration response is too large",
        ));
    }
    let written = unsafe {
        libc::send(
            connection.as_raw_fd(),
            encoded.as_ptr().cast(),
            encoded.len(),
            0,
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(written).ok() != Some(encoded.len()) {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial recovery administration packet",
        ));
    }
    Ok(())
}

fn peer_credentials(connection: &OwnedFd) -> io::Result<libc::ucred> {
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != size_of::<libc::ucred>() {
        return Err(io::Error::last_os_error());
    }
    Ok(credentials)
}

fn bind_admin_socket() -> Result<OwnedFd> {
    let directory = Path::new(ADMIN_DIR);
    if !directory.exists() {
        fs::create_dir(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    validate_root_path(directory, true)?;
    let socket = Path::new(ADMIN_SOCKET);
    if socket.exists() {
        return Err(NiralisdError::InvalidSocketPath(socket.to_path_buf()));
    }
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(NiralisdError::Io(io::Error::last_os_error()));
    }
    // SAFETY: socket returned a new descriptor.
    let listener = unsafe { OwnedFd::from_raw_fd(raw) };
    let address = socket_address(socket)?;
    let result = unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            size_of::<libc::sa_family_t>() as libc::socklen_t
                + socket.as_os_str().as_bytes().len() as libc::socklen_t
                + 1,
        )
    };
    if result != 0 {
        return Err(NiralisdError::Io(io::Error::last_os_error()));
    }
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    validate_root_path(socket, false)?;
    if unsafe { libc::listen(listener.as_raw_fd(), 16) } != 0 {
        return Err(NiralisdError::Io(io::Error::last_os_error()));
    }
    Ok(listener)
}

fn validate_root_path(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let expected = if directory { 0o700 } else { 0o600 };
    if metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o777 != expected
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.file_type().is_socket())
    {
        return Err(NiralisdError::InvalidSocketPath(path.to_path_buf()));
    }
    Ok(())
}

fn socket_address(path: &Path) -> Result<libc::sockaddr_un> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 || bytes.contains(&0) {
        return Err(NiralisdError::InvalidSocketPath(PathBuf::from(path)));
    }
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (index, byte) in bytes.iter().enumerate() {
        address.sun_path[index] = *byte as libc::c_char;
    }
    Ok(address)
}
