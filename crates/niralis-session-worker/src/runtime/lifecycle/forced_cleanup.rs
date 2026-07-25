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
        include!("../wait/forced_poll_cycle.rs");
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
