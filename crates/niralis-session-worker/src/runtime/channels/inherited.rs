#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InheritedSupervisorChannelError {
    MissingEnv,
    InvalidEnvValue,
    FcntlFailed,
    NotSocket,
    SocketInspectionDenied,
    WrongSocketType,
    PeerCredentialsUnavailable,
    UnexpectedPeerOwner,
}

fn socket_type(fd: RawFd) -> Result<libc::c_int, InheritedSupervisorChannelError> {
    let mut socket_type = 0 as libc::c_int;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if result == 0 {
        return Ok(socket_type);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => {
            Err(InheritedSupervisorChannelError::SocketInspectionDenied)
        }
        _ => Err(InheritedSupervisorChannelError::NotSocket),
    }
}

fn peer_credentials_for_fd(fd: RawFd) -> Option<libc::ucred> {
    let mut credentials = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    (result == 0).then_some(credentials)
}

fn take_inherited_supervisor_channel_inner() -> Result<UnixStream, InheritedSupervisorChannelError> {
    let env_name = niralis_session::WORKER_SUPERVISOR_FD_ENV;
    let value = std::env::var_os(env_name).ok_or(InheritedSupervisorChannelError::MissingEnv)?;
    let fd = value
        .to_str()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or(InheritedSupervisorChannelError::InvalidEnvValue)?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(InheritedSupervisorChannelError::FcntlFailed);
    }
    let socket_type = socket_type(fd)?;
    if socket_type != libc::SOCK_STREAM {
        return Err(InheritedSupervisorChannelError::WrongSocketType);
    }
    let credentials = peer_credentials_for_fd(fd)
        .ok_or(InheritedSupervisorChannelError::PeerCredentialsUnavailable)?;
    if credentials.uid != unsafe { libc::geteuid() } {
        return Err(InheritedSupervisorChannelError::UnexpectedPeerOwner);
    }
    std::env::remove_var(env_name);
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

#[cfg(feature = "worker-test-fixtures")]
pub fn take_inherited_supervisor_channel_for_test(
) -> Result<UnixStream, InheritedSupervisorChannelError> {
    let env_name = niralis_session::WORKER_SUPERVISOR_FD_ENV;
    let value = std::env::var_os(env_name).ok_or(InheritedSupervisorChannelError::MissingEnv)?;
    let fd = value
        .to_str()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or(InheritedSupervisorChannelError::InvalidEnvValue)?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(InheritedSupervisorChannelError::FcntlFailed);
    }
    match socket_type(fd) {
        Ok(socket_type) if socket_type != libc::SOCK_STREAM => {
            return Err(InheritedSupervisorChannelError::WrongSocketType);
        }
        Err(InheritedSupervisorChannelError::SocketInspectionDenied) => {
            std::env::remove_var(env_name);
            return Ok(unsafe { UnixStream::from_raw_fd(fd) });
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let credentials = peer_credentials_for_fd(fd)
        .ok_or(InheritedSupervisorChannelError::PeerCredentialsUnavailable)?;
    if credentials.uid != unsafe { libc::geteuid() } {
        return Err(InheritedSupervisorChannelError::UnexpectedPeerOwner);
    }
    std::env::remove_var(env_name);
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfUnixEnvironmentProbe {
    Supported,
    DeniedByEnvironment { operation: &'static str, errno: i32 },
    UnexpectedFailure { operation: &'static str, errno: i32 },
}

fn classify_af_unix_failure(operation: &'static str) -> AfUnixEnvironmentProbe {
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    match errno {
        libc::EPERM | libc::EACCES => AfUnixEnvironmentProbe::DeniedByEnvironment { operation, errno },
        _ => AfUnixEnvironmentProbe::UnexpectedFailure { operation, errno },
    }
}

pub fn probe_af_unix_environment_support() -> AfUnixEnvironmentProbe {
    let (mut left, mut right) = match UnixStream::pair() {
        Ok(pair) => pair,
        Err(_) => return classify_af_unix_failure("socketpair"),
    };
    if left.write_all(&[0x41]).is_err() {
        return classify_af_unix_failure("socketpair_send");
    }
    let mut byte = [0_u8; 1];
    if right.read_exact(&mut byte).is_err() {
        return classify_af_unix_failure("socketpair_recv");
    }
    let path = std::env::temp_dir().join(format!("niralis-af-unix-probe-{}.sock", std::process::id()));
    match UnixListener::bind(&path) {
        Ok(listener) => {
            drop(listener);
            let _ = std::fs::remove_file(&path);
            AfUnixEnvironmentProbe::Supported
        }
        Err(_) => classify_af_unix_failure("bind"),
    }
}

pub fn diagnose_inherited_supervisor_channel() -> Result<UnixStream, InheritedSupervisorChannelError> {
    take_inherited_supervisor_channel_inner()
}

pub fn take_inherited_supervisor_channel() -> Result<UnixStream, SessionError> {
    take_inherited_supervisor_channel_inner().map_err(|_| SessionError::WorkerProtocolFailed)
}

#[cfg(test)]
mod inherited_supervisor_channel_tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn inherited_supervisor_channel_accepts_socket_fd() {
        let _guard = env_lock().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (socket, _peer) = UnixStream::pair().expect("socketpair");
        let inherited_fd = socket.into_raw_fd();
        std::env::set_var(
            niralis_session::WORKER_SUPERVISOR_FD_ENV,
            inherited_fd.to_string(),
        );
        let inherited = match diagnose_inherited_supervisor_channel() {
            Ok(inherited) => inherited,
            Err(InheritedSupervisorChannelError::SocketInspectionDenied) => {
                eprintln!("skipping inherited socket validation: SO_TYPE denied by environment");
                std::env::remove_var(niralis_session::WORKER_SUPERVISOR_FD_ENV);
                return;
            }
            Err(error) => panic!("socket fd should validate: {error:?}"),
        };
        assert_eq!(
            peer_credentials(&inherited).expect("socket credentials").uid,
            unsafe { libc::geteuid() }
        );
        drop(inherited);
    }

    #[test]
    fn inherited_supervisor_channel_rejects_non_socket_fd() {
        let _guard = env_lock().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let file = std::fs::File::open("/dev/null").expect("open devnull");
        let inherited_fd = file.into_raw_fd();
        std::env::set_var(
            niralis_session::WORKER_SUPERVISOR_FD_ENV,
            inherited_fd.to_string(),
        );
        let result = diagnose_inherited_supervisor_channel();
        if matches!(
            result,
            Err(InheritedSupervisorChannelError::SocketInspectionDenied)
        ) {
            eprintln!("skipping non-socket validation: SO_TYPE denied by environment");
            std::env::remove_var(niralis_session::WORKER_SUPERVISOR_FD_ENV);
            return;
        }
        assert!(matches!(
            result,
            Err(InheritedSupervisorChannelError::NotSocket)
        ));
        std::env::remove_var(niralis_session::WORKER_SUPERVISOR_FD_ENV);
    }

    #[test]
    fn af_unix_probe_classifies_environment() {
        match probe_af_unix_environment_support() {
            AfUnixEnvironmentProbe::Supported
            | AfUnixEnvironmentProbe::DeniedByEnvironment { .. }
            | AfUnixEnvironmentProbe::UnexpectedFailure { .. } => {}
        }
    }
}
