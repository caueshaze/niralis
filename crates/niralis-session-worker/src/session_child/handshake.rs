
fn read_exec_status(fd: OwnedFd, timeout: Duration) -> Result<ExecStatus, SessionChildError> {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
    let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
    if ready == 0 {
        warn!(
            timeout_ms = millis,
            "timed out waiting for the session child exec status pipe"
        );
        return Err(SessionChildError::TimedOut);
    }
    if ready < 0 {
        warn!(
            errno = ?std::io::Error::last_os_error().raw_os_error(),
            "polling the session child exec status pipe failed"
        );
        return Err(SessionChildError::IoFailed);
    }
    if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        warn!(
            revents = pollfd.revents,
            "session child exec status pipe reported an error"
        );
        return Err(SessionChildError::IoFailed);
    }
    let mut payload = [0_u8; 512];
    let count = unsafe { libc::read(fd.as_raw_fd(), payload.as_mut_ptr().cast(), payload.len()) };
    if count == 0 {
        return Ok(ExecStatus::Success);
    }
    if count < 0 {
        warn!(
            errno = ?std::io::Error::last_os_error().raw_os_error(),
            "reading the session child exec status pipe failed"
        );
        return Err(SessionChildError::IoFailed);
    }
    let failure = serde_json::from_slice::<FinalExecFailure>(&payload[..count as usize])
        .map_err(|_| SessionChildError::ProtocolFailed)?;
    Ok(ExecStatus::Failure(failure))
}

impl Drop for SessionChildAttempt {
    fn drop(&mut self) {
        self.kill_and_reap();
        self.finish();
    }
}

fn remaining(deadline: Instant) -> Result<Duration, SessionChildError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or(SessionChildError::TimedOut)
}

fn wait_result<T: Send + 'static>(
    receiver: &Receiver<Result<T, SessionChildError>>,
    deadline: Instant,
) -> Result<T, SessionChildError> {
    let timeout = remaining(deadline)?;
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            warn!("timed out waiting for a private session-child message");
            Err(SessionChildError::TimedOut)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            warn!("private session-child response channel disconnected");
            Err(SessionChildError::IoFailed)
        }
    }
}

fn read_child_response(reader: &mut impl Read) -> Result<Vec<u8>, SessionChildError> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte).map_err(|error| {
            warn!(
                errno = ?error.raw_os_error(),
                error = %error,
                received_bytes = bytes.len(),
                "reading a private session-child message failed"
            );
            SessionChildError::IoFailed
        })?;
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
            return Err(SessionChildError::ProtocolFailed);
        }
    }
    if bytes.is_empty() || bytes.len() > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
        return Err(SessionChildError::ProtocolFailed);
    }
    Ok(bytes)
}

fn parse_response(
    bytes: &[u8],
) -> Result<SessionChildEnvelope<SessionChildResponse>, SessionChildError> {
    if !bytes.ends_with(b"\n") {
        return Err(SessionChildError::ProtocolFailed);
    }
    let line = &bytes[..bytes.len() - 1];
    if line.is_empty() || line.contains(&b'\n') {
        return Err(SessionChildError::ProtocolFailed);
    }
    serde_json::from_slice(line).map_err(|_| SessionChildError::ProtocolFailed)
}

fn kill_and_reap(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) | Err(_) => {}
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn run_child_process() -> i32 {
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    run_child_process_with_dependencies(
        stdin,
        stdout,
        &LibcPrivilegeDropper,
        &LinuxInheritedFdSanitizer,
        &LinuxPostDropAuditor,
        std::process::id(),
    )
}

#[cfg(test)]
pub(crate) fn run_child_process_with_dropper(
    reader: impl Read,
    writer: impl Write,
    dropper: &impl PrivilegeDropper,
    child_pid: u32,
) -> i32 {
    run_child_process_with_dependencies(
        reader,
        writer,
        dropper,
        &NoopFdSanitizer,
        &StubAudit,
        child_pid,
    )
}
