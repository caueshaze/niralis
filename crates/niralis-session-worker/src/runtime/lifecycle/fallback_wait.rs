fn wait_for_graceful_handoff() -> ! {
    let mut fd = libc::pollfd {
        fd: worker_signal_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        fd.revents = 0;
        let _ = unsafe { libc::poll(&mut fd, 1, -1) };
        while crate::termination::read_signal_fd(fd.fd)
            .ok()
            .flatten()
            .is_some()
        {}
    }
}

fn wait_for_prestarted_recovery(
    _scope: Box<dyn crate::payload_scope::AuthoritativePayloadScope>,
    _transaction: Box<dyn niralis_auth::AuthenticatedTransaction>,
    _terminal: VirtualTerminalGuard,
) -> ! {
    emit_fixture_event("PreStartedRecoveryHeld");
    wait_for_graceful_handoff()
}

fn wait_for_session_without_signal_fd(
    listener: Option<&UnixListener>,
    child_runner: &dyn crate::session_child::SessionChildRunner,
    worker_id: String,
    session_pid: u32,
    session_pgid: u32,
) -> Result<std::process::ExitStatus, SessionError> {
    // Test-only/backward-compatible seam for dependency-injected unit tests.
    // The production entrypoint always installs WORKER_SIGNAL_FD and therefore
    // cannot enter this PGID-based legacy path while Running.
    loop {
        match child_runner
            .wait_for_child_or_control(listener.map(AsRawFd::as_raw_fd))
            .map_err(|_| SessionError::AuthenticatedSessionFailed)?
        {
            crate::session_child::SessionChildWaitEvent::Exited(status) => return Ok(status),
            crate::session_child::SessionChildWaitEvent::ControlReady => {
                let listener = listener
                    .as_ref()
                    .ok_or(SessionError::AuthenticatedSessionFailed)?;
                match listener.accept() {
                    Ok((mut stream, _)) if peer_is_root(&stream) => {
                        let request = read_control_request(&mut stream)
                            .map_err(|_| SessionError::AuthenticatedSessionFailed)?;
                        match request.message {
                            WorkerControlRequest::Terminate {
                                worker_id: requested_worker_id,
                                expected_worker_pid,
                                expected_session_pid,
                                expected_session_pgid,
                            } if request.version == WORKER_CONTROL_PROTOCOL_VERSION
                                && requested_worker_id == worker_id
                                && expected_worker_pid == std::process::id()
                                && expected_session_pid == session_pid
                                && expected_session_pgid == session_pgid =>
                            {
                                return child_runner
                                    .terminate(SESSION_TERMINATION_GRACE)
                                    .map_err(|_| SessionError::AuthenticatedSessionFailed);
                            }
                            _ => return Err(SessionError::AuthenticatedSessionFailed),
                        }
                    }
                    Ok(_) => {}
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(SessionError::AuthenticatedSessionFailed),
                }
            }
        }
    }
}

fn peer_is_root(stream: &UnixStream) -> bool {
    peer_has_uid(stream, 0)
}

fn peer_has_uid(stream: &UnixStream, expected_uid: u32) -> bool {
    peer_credentials(stream).is_some_and(|credentials| credentials.uid == expected_uid)
}
