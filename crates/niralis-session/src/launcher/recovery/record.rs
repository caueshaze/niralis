use super::*;

#[derive(Debug)]
pub(crate) enum SupervisorRecoveryState {
    WorkerSpawned {
        previous_vt: PreviousVtIdentity,
    },
    PayloadPrepared {
        payload: SupervisorPreparedPayload,
        registration_nonce: String,
    },
    PayloadRegistered {
        payload: SupervisorPreparedPayload,
        registration_nonce: String,
    },
    PayloadReleased {
        payload: SupervisorPreparedPayload,
    },
    Started {
        payload: SupervisorPreparedPayload,
        runtime_id: RuntimeSessionId,
    },
    WorkerExitedUnexpectedly {
        payload: SupervisorPreparedPayload,
        classification: WorkerExitClassification,
    },
    EmergencyRecovery {
        payload: SupervisorPreparedPayload,
        classification: WorkerExitClassification,
    },
    Recovered {
        outcome: SupervisorEmergencyRecoveryOutcome,
    },
    Quarantined {
        stage: EmergencyRecoveryStage,
        reason: SupervisorRecoveryError,
        retained_identity: SupervisorRetainedRecoveryIdentity,
    },
}

#[derive(Debug)]
pub(crate) enum SupervisorRetainedRecoveryIdentity {
    PrePayload {
        previous_vt: PreviousVtIdentity,
    },
    Payload {
        payload: Box<SupervisorPreparedPayload>,
    },
    Unavailable,
}

#[derive(Debug)]
pub(crate) struct SupervisorSessionRecoveryRecord {
    pub(crate) lifecycle_id: String,
    pub(crate) worker_pid: u32,
    pub(crate) launcher_pid: u32,
    pub(crate) session_name: String,
    pub(crate) requested_username: String,
    pub(crate) worker_exit_status: Option<ExitStatus>,
    pub(crate) state: SupervisorRecoveryState,
}

impl SupervisorSessionRecoveryRecord {
    pub(crate) fn worker_spawned(
        lifecycle_id: String,
        worker_pid: u32,
        launcher_pid: u32,
        session: &StartedSession,
        previous_vt: PreviousVtIdentity,
    ) -> Self {
        Self {
            lifecycle_id,
            worker_pid,
            launcher_pid,
            session_name: session.session.id.clone(),
            requested_username: session.username.clone(),
            worker_exit_status: None,
            state: SupervisorRecoveryState::WorkerSpawned { previous_vt },
        }
    }

    pub(crate) fn phase_name(&self) -> &'static str {
        match &self.state {
            SupervisorRecoveryState::WorkerSpawned { .. } => "worker_spawned",
            SupervisorRecoveryState::PayloadPrepared { .. } => "payload_prepared",
            SupervisorRecoveryState::PayloadRegistered { .. } => "payload_registered",
            SupervisorRecoveryState::PayloadReleased { .. } => "payload_released",
            SupervisorRecoveryState::Started { .. } => "started",
            SupervisorRecoveryState::WorkerExitedUnexpectedly { .. } => {
                "worker_exited_unexpectedly"
            }
            SupervisorRecoveryState::EmergencyRecovery { classification, .. } => {
                let _ = classification;
                "emergency_recovery"
            }
            SupervisorRecoveryState::Recovered { outcome } => {
                let _ = outcome;
                "recovered"
            }
            SupervisorRecoveryState::Quarantined {
                stage,
                reason,
                retained_identity,
            } => {
                if let SupervisorRetainedRecoveryIdentity::PrePayload { previous_vt } =
                    retained_identity
                {
                    let _ = previous_vt.number;
                }
                let _ = (stage, reason);
                "quarantined"
            }
        }
    }

    pub(crate) fn payload_identity(&self) -> Option<&crate::PayloadScopeIdentity> {
        match &self.state {
            SupervisorRecoveryState::PayloadPrepared { payload, .. }
            | SupervisorRecoveryState::PayloadRegistered { payload, .. }
            | SupervisorRecoveryState::PayloadReleased { payload }
            | SupervisorRecoveryState::Started { payload, .. }
            | SupervisorRecoveryState::WorkerExitedUnexpectedly { payload, .. }
            | SupervisorRecoveryState::EmergencyRecovery { payload, .. } => {
                Some(payload.boundary.identity())
            }
            SupervisorRecoveryState::Quarantined {
                retained_identity: SupervisorRetainedRecoveryIdentity::Payload { payload },
                ..
            } => Some(payload.boundary.identity()),
            _ => None,
        }
    }

    pub(crate) fn take_state_for_transition(&mut self) -> SupervisorRecoveryState {
        std::mem::replace(
            &mut self.state,
            SupervisorRecoveryState::Quarantined {
                stage: EmergencyRecoveryStage::RecoveryRecordValidation,
                reason: SupervisorRecoveryError::InvalidRecord,
                retained_identity: SupervisorRetainedRecoveryIdentity::Unavailable,
            },
        )
    }

    pub(crate) fn quarantine(
        &mut self,
        stage: EmergencyRecoveryStage,
        reason: SupervisorRecoveryError,
    ) {
        let state = self.take_state_for_transition();
        let retained_identity = match state {
            SupervisorRecoveryState::WorkerSpawned { previous_vt } => {
                SupervisorRetainedRecoveryIdentity::PrePayload { previous_vt }
            }
            SupervisorRecoveryState::PayloadPrepared { payload, .. }
            | SupervisorRecoveryState::PayloadRegistered { payload, .. }
            | SupervisorRecoveryState::PayloadReleased { payload }
            | SupervisorRecoveryState::Started { payload, .. }
            | SupervisorRecoveryState::WorkerExitedUnexpectedly { payload, .. }
            | SupervisorRecoveryState::EmergencyRecovery { payload, .. } => {
                SupervisorRetainedRecoveryIdentity::Payload {
                    payload: Box::new(payload),
                }
            }
            SupervisorRecoveryState::Quarantined {
                retained_identity, ..
            } => retained_identity,
            SupervisorRecoveryState::Recovered { .. } => {
                SupervisorRetainedRecoveryIdentity::Unavailable
            }
        };
        self.state = SupervisorRecoveryState::Quarantined {
            stage,
            reason,
            retained_identity,
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SeatLifecycle {
    Free,
    Active {
        lifecycle_id: String,
    },
    Recovering {
        lifecycle_id: String,
        phase: &'static str,
        reason: WorkerExitClassification,
    },
    Quarantined {
        lifecycle_id: String,
        stage: EmergencyRecoveryStage,
        reason: SupervisorRecoveryError,
    },
}
