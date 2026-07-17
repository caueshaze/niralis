use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerTerminationSignal {
    Sigterm,
    Sigint,
    Sighup,
}

impl WorkerTerminationSignal {
    pub fn from_raw(signal: libc::c_int) -> Option<Self> {
        match signal {
            libc::SIGTERM => Some(Self::Sigterm),
            libc::SIGINT => Some(Self::Sigint),
            libc::SIGHUP => Some(Self::Sighup),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaderExit {
    ExitedZero,
    ExitedNonZero(i32),
    KilledBySignal(i32),
    Other(i32),
}

impl LeaderExit {
    pub fn from_status(status: std::process::ExitStatus) -> Self {
        if let Some(code) = status.code() {
            if code == 0 {
                Self::ExitedZero
            } else {
                Self::ExitedNonZero(code)
            }
        } else if let Some(signal) = status.signal() {
            Self::KilledBySignal(signal)
        } else {
            Self::Other(status.into_raw())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationCause {
    InternalTerminateRequest,
    WorkerSignal(WorkerTerminationSignal),
    SupervisorDisconnected,
    LeaderExited(LeaderExit),
    RuntimeFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryTerminalObservation {
    CgroupEventRevalidated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracefulTerminationError {
    BoundaryObserver,
    ScopeOperation(crate::payload_scope::PayloadScopeError),
    Timer,
    Poll,
    LeaderReap,
    Signal,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryReason {
    BoundaryIdentityChanged,
    BoundaryIdentityUnproven,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracefulTerminationOutcome {
    BoundaryTerminalCandidate {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        observation: BoundaryTerminalObservation,
    },
    DeadlineExpired {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
    },
    InfrastructureFailure {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        error: GracefulTerminationError,
    },
    RecoveryRequired {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        reason: RecoveryReason,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct BoundaryEmptyProof {
    unit_name: String,
    invocation_id: String,
    control_group: String,
    leader_exit: LeaderExit,
}

impl BoundaryEmptyProof {
    pub(crate) fn new(
        identity: &niralis_session::PayloadScopeIdentity,
        control_group: &str,
        leader_exit: LeaderExit,
    ) -> Self {
        Self {
            unit_name: identity.unit_name.clone(),
            invocation_id: identity.invocation_id.clone(),
            control_group: control_group.to_owned(),
            leader_exit,
        }
    }

    pub fn leader_exit(&self) -> &LeaderExit {
        &self.leader_exit
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EscalationEligibility {
    Eligible {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
    },
    InfrastructureFailure {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        error: GracefulTerminationError,
    },
    RecoveryRequired {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        reason: RecoveryReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedTerminationStage {
    Eligibility,
    PreKillValidation,
    Kill,
    PostKillValidation,
    LeaderReap,
    BoundaryObservation,
    EmptyProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForcedTerminationError {
    ScopeOperation(crate::payload_scope::PayloadScopeError),
    Timer,
    Poll,
    LeaderReap,
    Signal,
    Control,
    BoundaryObserver,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ForcedTerminationOutcome {
    BoundaryEmpty {
        proof: BoundaryEmptyProof,
        leader_exit: LeaderExit,
    },
    ForcedDeadlineExpired {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
    },
    InfrastructureFailure {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        stage: ForcedTerminationStage,
        error: ForcedTerminationError,
    },
    RecoveryRequired {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        reason: RecoveryReason,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum GracefulFinalizationDecision {
    FinalizeCooperative(BoundaryEmptyProof),
    NeedsEscalation(EscalationEligibility),
    RecoveryRequired {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        reason: RecoveryReason,
    },
}

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
