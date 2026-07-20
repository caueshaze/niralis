
fn wait_for_session_with_grace(
    listener: Option<&UnixListener>,
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

#[cfg(test)]
fn finalize_session_after_empty_proof(
    scope: &mut dyn crate::payload_scope::AuthoritativePayloadScope,
    mut transaction: Box<dyn niralis_auth::AuthenticatedTransaction>,
    terminal: &mut VirtualTerminalGuard,
    proof: crate::termination::BoundaryEmptyProof,
    forced: bool,
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
    if forced {
        info!("forced session finalization complete");
    } else {
        info!("cooperative session finalization complete");
    }
    emit_fixture_event("WorkerReturning");
    if matches!(proof.leader_exit(), crate::termination::LeaderExit::ExitedZero)
        || (forced
            && matches!(
                proof.leader_exit(),
                crate::termination::LeaderExit::KilledBySignal(libc::SIGKILL)
            ))
    {
        Ok(())
    } else {
        Err(SessionError::AuthenticatedSessionFailed)
    }
}

fn finalize_session_after_empty_proof_with_vt_report(
    scope: &mut dyn crate::payload_scope::AuthoritativePayloadScope,
    mut transaction: Box<dyn niralis_auth::AuthenticatedTransaction>,
    terminal: &mut VirtualTerminalGuard,
    proof: crate::termination::BoundaryEmptyProof,
    forced: bool,
    worker_id: &str,
    registration_nonce: &str,
    report_expectation: TerminalReportExpectation,
) -> Result<(), SessionError> {
    info!("releasing pinned systemd unit reference");
    if let Err(error) = scope.release_pin() { warn!(?error, "pinned unit reference release failed after empty proof"); }
    info!("closing worker PAM transaction after empty proof");
    transaction.close_session().map_err(|error| {
        warn!(?error, "worker PAM close failed after empty proof");
        SessionError::AuthenticatedSessionFailed
    })?;
    drop(transaction);
    if matches!(
        report_expectation,
        TerminalReportExpectation::UnavailableAfterSupervisorDisconnect
    ) || supervisor_channel_is_closed()
    {
        info!("terminal session cleanup completed after supervisor disconnect");
        let result = terminal.release().map_err(|error| {
            warn!(?error, "session VT release failed after supervisor disconnect");
            SessionError::AuthenticatedSessionFailed
        });
        let delivery = TerminalReportDelivery::UnavailableAfterSupervisorDisconnect;
        info!(?delivery, "terminal report unavailable because supervisor channel is closed");
        result?;
        info!("worker exiting with locally finalized session state");
        emit_fixture_event("WorkerReturning");
        return terminal_local_finalization_result(&proof, forced);
    }
    let identity = scope.identity().clone();
    let (stream, attempt_id) = begin_terminal_vt_cleanup(worker_id, registration_nonce, &identity)?;
    info!("releasing session VT after durable supervisor intent");
    match terminal.release() {
        Ok(()) => {
            complete_terminal_vt_cleanup(stream, worker_id, registration_nonce, attempt_id, niralis_session::TerminalVtCleanupResult::Released)?;
            let delivery = TerminalReportDelivery::Delivered;
            debug!(?delivery, "terminal VT cleanup result delivered to supervisor");
        }
        Err(crate::vt::VirtualTerminalError::CleanupOperationFailed { stage: "disallocate", errno }) if errno == libc::EBUSY => {
            warn!(errno, "session VT disallocation is busy; supervisor quarantine is durable");
            complete_terminal_vt_cleanup(stream, worker_id, registration_nonce, attempt_id, niralis_session::TerminalVtCleanupResult::VtDisallocateBusy)?;
            emit_fixture_event("WorkerVtBusyAcknowledged");
            return Ok(());
        }
        Err(error) => { warn!(?error, "session VT release failed after durable intent"); return Err(SessionError::AuthenticatedSessionFailed); }
    }
    if forced { info!("forced session finalization complete"); } else { info!("cooperative session finalization complete"); }
    emit_fixture_event("WorkerReturning");
    terminal_local_finalization_result(&proof, forced)
}

fn terminal_local_finalization_result(
    proof: &crate::termination::BoundaryEmptyProof,
    forced: bool,
) -> Result<(), SessionError> {
    if matches!(proof.leader_exit(), crate::termination::LeaderExit::ExitedZero)
        || (forced
            && matches!(
                proof.leader_exit(),
                crate::termination::LeaderExit::KilledBySignal(libc::SIGKILL)
            ))
    {
        Ok(())
    } else {
        Err(SessionError::AuthenticatedSessionFailed)
    }
}

struct ForcedWaitContext<'a> {
    listener: Option<&'a UnixListener>,
    child_runner: &'a dyn crate::session_child::SessionChildRunner,
    worker_id: &'a str,
    session_pid: u32,
    session_pgid: u32,
    authoritative_scope: &'a dyn crate::payload_scope::AuthoritativePayloadScope,
    expected_control_uid: u32,
}

fn wait_for_forced_cleanup(
    context: ForcedWaitContext<'_>,
    cause: crate::termination::TerminationCause,
    leader_exit: Option<crate::termination::LeaderExit>,
    timeout: Duration,
) -> crate::termination::ForcedTerminationOutcome {
    use crate::termination::{
        ForcedTerminationCoordinator, ForcedTerminationError, ForcedTerminationStage, LeaderExit,
        WorkerTerminationSignal,
    };
    let ForcedWaitContext {
        listener,
        child_runner,
        worker_id,
        session_pid,
        session_pgid,
        authoritative_scope,
        expected_control_uid,
    } = context;
    let mut coordinator = match ForcedTerminationCoordinator::new(cause, leader_exit) {
        Ok(coordinator) => coordinator,
        Err(_) => {
            return crate::termination::ForcedTerminationOutcome::InfrastructureFailure {
                cause: crate::termination::TerminationCause::RuntimeFailure,
                leader_exit: None,
                stage: ForcedTerminationStage::Eligibility,
                error: ForcedTerminationError::Timer,
            }
        }
    };
    let signal_fd = worker_signal_fd();
    let supervisor_fd = supervisor_channel_fd();
    let pidfd = child_runner.authoritative_pidfd();
    if signal_fd < 0 || (coordinator.leader_exit().is_none() && pidfd < 0) {
        return coordinator.infrastructure(
            ForcedTerminationStage::Eligibility,
            ForcedTerminationError::LeaderReap,
        );
    }
    let mut observer = match coordinator.begin(timeout, authoritative_scope) {
        Ok(observer) => observer,
        Err(outcome) => return outcome,
    };
    info!(unit = %authoritative_scope.identity().unit_name, invocation_id = %authoritative_scope.identity().invocation_id, "forced payload termination requested");
    emit_fixture_event("ForcedTerminationRequested:count=1");
    emit_fixture_event("ForcedTimerArmed");
    info!(timeout_ms = timeout.as_millis(), "waiting for forced boundary cleanup");
    let mut leader_reaped = coordinator.leader_exit().is_some();

    if let Some(outcome) = try_forced_empty_proof(authoritative_scope, &mut coordinator) {
        return outcome;
    }
    loop {
        include!("wait/forced_poll_cycle.rs");
    }
}

fn try_forced_empty_proof(
    scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
    coordinator: &mut crate::termination::ForcedTerminationCoordinator,
) -> Option<crate::termination::ForcedTerminationOutcome> {
    use crate::termination::ForcedTerminationStage;
    let proof_may_be_attempted = match scope.boundary_appears_terminal() {
        Ok(value) => value,
        // After a confirmed SIGKILL, disappearance is resolved only by the
        // strong two-resolution/cgroup policy inside prove_empty_boundary().
        Err(crate::payload_scope::PayloadScopeError::InvocationUnavailable) => true,
        Err(error) => {
            return Some(
                coordinator.scope_error(ForcedTerminationStage::BoundaryObservation, error),
            )
        }
    };
    if !proof_may_be_attempted {
        return None;
    }
    let leader_exit = coordinator.leader_exit()?.clone();
    match scope.prove_empty_boundary(&leader_exit) {
        Ok(proof) => {
            info!("forced boundary empty proof established");
            emit_fixture_event("BoundaryEmptyProofAccepted");
            Some(coordinator.boundary_empty(proof))
        }
        Err(crate::payload_scope::PayloadScopeError::BoundaryNotEmpty
        | crate::payload_scope::PayloadScopeError::UnitNotTerminal) => None,
        Err(crate::payload_scope::PayloadScopeError::UnitReplaced) => Some(
            coordinator.scope_error(
                ForcedTerminationStage::EmptyProof,
                crate::payload_scope::PayloadScopeError::UnitReplaced,
            ),
        ),
        Err(error) => Some(coordinator.scope_error(ForcedTerminationStage::EmptyProof, error)),
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
