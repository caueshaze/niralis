
fn wait_for_session_with_grace(
    listener: Option<UnixListener>,
    child_runner: &dyn crate::session_child::SessionChildRunner,
    worker_id: String,
    session_pid: u32,
    session_pgid: u32,
    authoritative_scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
    grace: Duration,
    expected_control_uid: u32,
) -> Result<SessionWaitResult, SessionError> {
    use crate::termination::{
        BoundaryTerminalObservation, GracefulTerminationCoordinator, GracefulTerminationError,
        LeaderExit, TerminationCause, WorkerTerminationSignal,
    };
    let mut coordinator = match GracefulTerminationCoordinator::new() {
        Ok(coordinator) => coordinator,
        Err(_) => {
            return Ok(SessionWaitResult::Graceful(
                crate::termination::GracefulTerminationOutcome::InfrastructureFailure {
                    cause: TerminationCause::RuntimeFailure,
                    leader_exit: None,
                    error: GracefulTerminationError::Timer,
                },
            ))
        }
    };
    let timer_flags = unsafe { libc::fcntl(coordinator.timer_fd(), libc::F_GETFD) };
    if timer_flags >= 0 && timer_flags & libc::FD_CLOEXEC != 0 {
        emit_fixture_event("TimerFdCloexec");
    }
    let signal_fd = worker_signal_fd();
    let supervisor_fd = supervisor_channel_fd();
    if signal_fd < 0 {
        return wait_for_session_without_signal_fd(
            listener,
            child_runner,
            worker_id,
            session_pid,
            session_pgid,
        )
        .map(SessionWaitResult::Legacy);
    }
    let pidfd = child_runner.authoritative_pidfd();
    if pidfd < 0 {
        return Ok(SessionWaitResult::Graceful(
            coordinator.infrastructure(GracefulTerminationError::LeaderReap),
        ));
    }
    let mut leader_reaped = false;
    let mut observer: Option<Box<dyn crate::payload_scope::PayloadBoundaryObserver>> = None;
    loop {
        include!("wait/poll_cycle.rs");
    }
}

enum SessionWaitResult {
    Legacy(std::process::ExitStatus),
    Graceful(crate::termination::GracefulTerminationOutcome),
}

fn finalize_cooperative_session(
    scope: &mut dyn crate::payload_scope::AuthoritativePayloadScope,
    mut transaction: Box<dyn niralis_auth::AuthenticatedTransaction>,
    terminal: &mut VirtualTerminalGuard,
    proof: crate::termination::BoundaryEmptyProof,
) -> Result<(), SessionError> {
    info!("releasing pinned systemd unit reference");
    if let Err(error) = scope.release_pin() {
        warn!(
            ?error,
            "pinned unit reference release failed after empty proof"
        );
    }
    info!("closing worker PAM transaction after empty proof");
    let pam_result = transaction.close_session().map_err(|error| {
        warn!(?error, "worker PAM close failed after empty proof");
        SessionError::AuthenticatedSessionFailed
    });
    drop(transaction);
    info!("releasing session VT after PAM close");
    let vt_result = terminal.release().map_err(|error| {
        warn!(?error, "session VT release failed after PAM close");
        SessionError::AuthenticatedSessionFailed
    });
    pam_result?;
    vt_result?;
    info!("cooperative session finalization complete");
    emit_fixture_event("WorkerReturning");
    if matches!(
        proof.leader_exit(),
        crate::termination::LeaderExit::ExitedZero
    ) {
        Ok(())
    } else {
        Err(SessionError::AuthenticatedSessionFailed)
    }
}

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
    listener: Option<UnixListener>,
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
            .wait_for_child_or_control(listener.as_ref().map(AsRawFd::as_raw_fd))
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
