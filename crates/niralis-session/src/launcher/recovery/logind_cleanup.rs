use super::*;

pub(crate) fn cleanup_logind_session(
    identity: &SupervisorLogindSessionIdentity,
) -> Result<SupervisorLogindCleanupResult, SupervisorRecoveryError> {
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?
        .method_timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        LOGIND_DESTINATION,
        LOGIND_MANAGER_PATH,
        LOGIND_MANAGER_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let path: OwnedObjectPath = match manager.call("GetSession", &(identity.id.as_str(),)) {
        Ok(path) => path,
        Err(zbus::Error::MethodError(name, _, _))
            if matches!(
                name.as_str(),
                "org.freedesktop.login1.NoSuchSession" | "org.freedesktop.DBus.Error.UnknownObject"
            ) =>
        {
            return Ok(SupervisorLogindCleanupResult::AlreadyGone)
        }
        Err(_) => return Err(SupervisorRecoveryError::LogindUnavailable),
    };
    if path.as_str() != identity.object_path {
        return Err(SupervisorRecoveryError::LogindIdentityChanged);
    }
    let observed = read_logind_identity(&connection, &path, identity.id.clone())?;
    if &observed != identity {
        return Err(SupervisorRecoveryError::LogindIdentityChanged);
    }
    let watch = LogindRemovalObserver::open(identity.id.as_str())?;
    info!(session_id = %identity.id.as_str(), "terminating orphaned logind session");
    match manager.call::<_, _, ()>("TerminateSession", &(identity.id.as_str(),)) {
        Ok(()) => {}
        Err(zbus::Error::MethodError(name, _, _))
            if matches!(
                name.as_str(),
                "org.freedesktop.login1.NoSuchSession" | "org.freedesktop.DBus.Error.UnknownObject"
            ) && !watch.session_path.exists() =>
        {
            return Ok(SupervisorLogindCleanupResult::AlreadyGone)
        }
        Err(_) => return Err(SupervisorRecoveryError::LogindUnavailable),
    }
    watch.wait(LOGIND_REMOVAL_TIMEOUT)?;
    info!(session_id = %identity.id.as_str(), "logind session removed after worker death");
    Ok(SupervisorLogindCleanupResult::Removed)
}

pub(crate) fn logind_session_absent(
    identity: &SupervisorLogindSessionIdentity,
) -> Result<bool, SupervisorRecoveryError> {
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        LOGIND_DESTINATION,
        LOGIND_MANAGER_PATH,
        LOGIND_MANAGER_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    match manager.call::<_, _, OwnedObjectPath>("GetSession", &(identity.id.as_str(),)) {
        Ok(path) if path.as_str() == identity.object_path => {
            let observer = LogindRemovalObserver::open(identity.id.as_str())?;
            match manager.call::<_, _, OwnedObjectPath>("GetSession", &(identity.id.as_str(),)) {
                Err(zbus::Error::MethodError(name, _, _))
                    if matches!(
                        name.as_str(),
                        "org.freedesktop.login1.NoSuchSession"
                            | "org.freedesktop.DBus.Error.UnknownObject"
                    ) =>
                {
                    Ok(true)
                }
                Ok(second) if second == path => {
                    observer.wait(Duration::from_secs(2)).map(|()| true)
                }
                Ok(_) => Err(SupervisorRecoveryError::LogindIdentityChanged),
                Err(_) => Err(SupervisorRecoveryError::LogindUnavailable),
            }
        }
        Ok(_) => Err(SupervisorRecoveryError::LogindIdentityChanged),
        Err(zbus::Error::MethodError(name, _, _))
            if matches!(
                name.as_str(),
                "org.freedesktop.login1.NoSuchSession" | "org.freedesktop.DBus.Error.UnknownObject"
            ) =>
        {
            Ok(true)
        }
        Err(_) => Err(SupervisorRecoveryError::LogindUnavailable),
    }
}

pub(crate) struct LogindRemovalObserver {
    pub(crate) fd: OwnedFd,
    pub(crate) watch: libc::c_int,
    pub(crate) session_path: PathBuf,
}

impl LogindRemovalObserver {
    pub(crate) fn open(id: &str) -> Result<Self, SupervisorRecoveryError> {
        if id.is_empty()
            || id.len() > 128
            || id
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
        {
            return Err(SupervisorRecoveryError::LogindIdentityChanged);
        }
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(SupervisorRecoveryError::LogindUnavailable);
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let directory = CString::new("/run/systemd/sessions")
            .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
        let watch = unsafe {
            libc::inotify_add_watch(
                fd.as_raw_fd(),
                directory.as_ptr(),
                libc::IN_DELETE | libc::IN_MOVED_FROM,
            )
        };
        if watch < 0 {
            return Err(SupervisorRecoveryError::LogindUnavailable);
        }
        Ok(Self {
            fd,
            watch,
            session_path: Path::new("/run/systemd/sessions").join(id),
        })
    }

    pub(crate) fn wait(self, timeout: Duration) -> Result<(), SupervisorRecoveryError> {
        if !self.session_path.exists() {
            return Ok(());
        }
        let timer = MonotonicTimer::arm(timeout)?;
        loop {
            let mut descriptors = [
                libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: timer.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            if unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) } < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SupervisorRecoveryError::LogindUnavailable);
            }
            if descriptors[1].revents & libc::POLLIN != 0 {
                return Err(SupervisorRecoveryError::LogindRemovalTimedOut);
            }
            if descriptors[0].revents & libc::POLLIN != 0 {
                let mut bytes = [0u8; 4096];
                let _ = unsafe {
                    libc::read(self.fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len())
                };
                if !self.session_path.exists() {
                    return Ok(());
                }
            }
        }
    }
}

impl Drop for LogindRemovalObserver {
    fn drop(&mut self) {
        let _ = unsafe { libc::inotify_rm_watch(self.fd.as_raw_fd(), self.watch) };
    }
}
