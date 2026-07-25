
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
        include!("../wait/poll_cycle.rs");
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
        return finalize_terminal_after_supervisor_disconnect(terminal, &proof, forced);
    }
    let identity = scope.identity().clone();
    let (stream, attempt_id) = match begin_terminal_vt_cleanup(worker_id, registration_nonce, &identity) {
        Ok(value) => value,
        Err(error) if supervisor_channel_is_closed() => {
            warn!(?error, "terminal report intent lost to a disconnected supervisor");
            return finalize_terminal_after_supervisor_disconnect(terminal, &proof, forced);
        }
        Err(error) => return Err(error),
    };
    info!("releasing session VT after durable supervisor intent");
    match terminal.release() {
        Ok(()) => {
            if let Err(error) = complete_terminal_vt_cleanup(stream, worker_id, registration_nonce, attempt_id, niralis_session::TerminalVtCleanupResult::Released) {
                if supervisor_channel_is_closed() {
                    warn!(?error, "terminal report result lost to a disconnected supervisor");
                    return finalize_terminal_after_supervisor_disconnect_completed_vt(&proof, forced);
                }
                return Err(error);
            }
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

fn finalize_terminal_after_supervisor_disconnect(
    terminal: &mut VirtualTerminalGuard,
    proof: &crate::termination::BoundaryEmptyProof,
    forced: bool,
) -> Result<(), SessionError> {
    info!("terminal session cleanup completed after supervisor disconnect");
    terminal.release().map_err(|error| {
        warn!(?error, "session VT release failed after supervisor disconnect");
        SessionError::AuthenticatedSessionFailed
    })?;
    let delivery = TerminalReportDelivery::UnavailableAfterSupervisorDisconnect;
    info!(?delivery, "terminal report unavailable because supervisor channel is closed");
    finalize_terminal_after_supervisor_disconnect_completed_vt(proof, forced)
}

fn finalize_terminal_after_supervisor_disconnect_completed_vt(
    proof: &crate::termination::BoundaryEmptyProof,
    forced: bool,
) -> Result<(), SessionError> {
    info!("worker exiting with locally finalized session state");
    emit_fixture_event("WorkerReturning");
    terminal_local_finalization_result(proof, forced)
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
