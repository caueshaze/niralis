#[cfg(feature = "worker-test-fixtures")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureSupervisorTransportError {
    MissingEnv,
    InvalidTransport,
    InvalidFd,
    FcntlFailed,
}

#[cfg(feature = "worker-test-fixtures")]
pub struct FixtureSupervisorTransport {
    reader: File,
    writer: File,
}

#[cfg(feature = "worker-test-fixtures")]
impl Read for FixtureSupervisorTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

#[cfg(feature = "worker-test-fixtures")]
impl Write for FixtureSupervisorTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(feature = "worker-test-fixtures")]
fn take_fixture_supervisor_transport_fd(env_name: &str) -> Result<RawFd, FixtureSupervisorTransportError> {
    let value = std::env::var_os(env_name).ok_or(FixtureSupervisorTransportError::MissingEnv)?;
    let fd = value
        .to_str()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or(FixtureSupervisorTransportError::InvalidFd)?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(FixtureSupervisorTransportError::FcntlFailed);
    }
    Ok(fd)
}

#[cfg(feature = "worker-test-fixtures")]
pub fn take_fixture_supervisor_transport_for_test() -> Result<FixtureSupervisorTransport, FixtureSupervisorTransportError> {
    let mode = std::env::var(niralis_session::FIXTURE_SUPERVISOR_TRANSPORT_ENV)
        .map_err(|_| FixtureSupervisorTransportError::MissingEnv)?;
    if mode != "pipe" {
        return Err(FixtureSupervisorTransportError::InvalidTransport);
    }
    let read_fd = take_fixture_supervisor_transport_fd(niralis_session::FIXTURE_SUPERVISOR_READ_FD_ENV)?;
    let write_fd = take_fixture_supervisor_transport_fd(niralis_session::FIXTURE_SUPERVISOR_WRITE_FD_ENV)?;
    std::env::remove_var(niralis_session::FIXTURE_SUPERVISOR_TRANSPORT_ENV);
    std::env::remove_var(niralis_session::FIXTURE_SUPERVISOR_READ_FD_ENV);
    std::env::remove_var(niralis_session::FIXTURE_SUPERVISOR_WRITE_FD_ENV);
    Ok(FixtureSupervisorTransport {
        reader: unsafe { File::from_raw_fd(read_fd) },
        writer: unsafe { File::from_raw_fd(write_fd) },
    })
}
