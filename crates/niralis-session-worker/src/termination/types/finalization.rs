pub fn consume_graceful_outcome(
    outcome: GracefulTerminationOutcome,
    scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
) -> GracefulFinalizationDecision {
    match outcome {
        GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause,
            leader_exit: Some(leader_exit),
            ..
        } => match scope.prove_empty_boundary(&leader_exit) {
            Ok(proof) => GracefulFinalizationDecision::FinalizeCooperative(proof),
            Err(crate::payload_scope::PayloadScopeError::UnitReplaced) => {
                GracefulFinalizationDecision::RecoveryRequired {
                    cause,
                    leader_exit: Some(leader_exit),
                    reason: RecoveryReason::BoundaryIdentityChanged,
                }
            }
            Err(crate::payload_scope::PayloadScopeError::WorkerInsideBoundary
            | crate::payload_scope::PayloadScopeError::InvalidIdentity
            | crate::payload_scope::PayloadScopeError::CgroupMismatch
            | crate::payload_scope::PayloadScopeError::InvalidMembership) => {
                GracefulFinalizationDecision::RecoveryRequired {
                    cause,
                    leader_exit: Some(leader_exit),
                    reason: RecoveryReason::BoundaryIdentityUnproven,
                }
            }
            Err(crate::payload_scope::PayloadScopeError::BoundaryNotEmpty
            | crate::payload_scope::PayloadScopeError::UnitNotTerminal) => {
                eligibility_after_identity_validation(cause, Some(leader_exit), scope)
            }
            Err(error) => GracefulFinalizationDecision::NeedsEscalation(
                EscalationEligibility::InfrastructureFailure {
                    cause,
                    leader_exit: Some(leader_exit),
                    error: GracefulTerminationError::ScopeOperation(error),
                },
            ),
        },
        GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause,
            leader_exit: None,
            ..
        } => eligibility_after_identity_validation(cause, None, scope),
        GracefulTerminationOutcome::DeadlineExpired { cause, leader_exit } => {
            eligibility_after_identity_validation(cause, leader_exit, scope)
        }
        GracefulTerminationOutcome::InfrastructureFailure {
            cause,
            leader_exit,
            error,
        } => GracefulFinalizationDecision::NeedsEscalation(
            EscalationEligibility::InfrastructureFailure {
                cause,
                leader_exit,
                error,
            },
        ),
        GracefulTerminationOutcome::RecoveryRequired {
            cause,
            leader_exit,
            reason,
        } => GracefulFinalizationDecision::RecoveryRequired {
            cause,
            leader_exit,
            reason,
        },
    }
}

fn eligibility_after_identity_validation(
    cause: TerminationCause,
    leader_exit: Option<LeaderExit>,
    scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
) -> GracefulFinalizationDecision {
    match scope.validate_forced_termination_eligibility() {
        Ok(()) => GracefulFinalizationDecision::NeedsEscalation(
            EscalationEligibility::Eligible { cause, leader_exit },
        ),
        Err(crate::payload_scope::PayloadScopeError::UnitReplaced) => {
            GracefulFinalizationDecision::NeedsEscalation(
                EscalationEligibility::RecoveryRequired {
                    cause,
                    leader_exit,
                    reason: RecoveryReason::BoundaryIdentityChanged,
                },
            )
        }
        Err(crate::payload_scope::PayloadScopeError::WorkerInsideBoundary
        | crate::payload_scope::PayloadScopeError::InvalidIdentity
        | crate::payload_scope::PayloadScopeError::CgroupMismatch
        | crate::payload_scope::PayloadScopeError::InvalidMembership) => {
            GracefulFinalizationDecision::NeedsEscalation(
                EscalationEligibility::RecoveryRequired {
                    cause,
                    leader_exit,
                    reason: RecoveryReason::BoundaryIdentityUnproven,
                },
            )
        }
        Err(error) => GracefulFinalizationDecision::NeedsEscalation(
            EscalationEligibility::InfrastructureFailure {
                cause,
                leader_exit,
                error: GracefulTerminationError::ScopeOperation(error),
            },
        ),
    }
}
