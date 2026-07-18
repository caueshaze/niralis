use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupervisorBoundaryState {
    Populated,
    Empty,
    Absent,
}

pub(crate) struct SupervisorEmergencyRecoveryCoordinator<'a> {
    pub(crate) provider: &'a dyn SupervisorRecoveryProvider,
}

impl<'a> SupervisorEmergencyRecoveryCoordinator<'a> {
    pub(crate) fn new(provider: &'a dyn SupervisorRecoveryProvider) -> Self {
        Self { provider }
    }

    pub(crate) fn recover(
        &self,
        record: &mut SupervisorSessionRecoveryRecord,
        worker_exit: ExitStatus,
    ) -> SupervisorEmergencyRecoveryOutcome {
        let classification = classify_worker_exit(record, worker_exit);
        record.worker_exit_status = Some(worker_exit);
        info!(lifecycle_id = %record.lifecycle_id, "starting emergency supervisor recovery");
        let state = record.take_state_for_transition();
        let payload = match state {
            SupervisorRecoveryState::PayloadPrepared { payload, .. }
            | SupervisorRecoveryState::PayloadRegistered { payload, .. }
            | SupervisorRecoveryState::PayloadReleased { payload }
            | SupervisorRecoveryState::Started { payload, .. }
            | SupervisorRecoveryState::WorkerExitedUnexpectedly { payload, .. }
            | SupervisorRecoveryState::EmergencyRecovery { payload, .. } => payload,
            other => {
                record.state = other;
                return SupervisorEmergencyRecoveryOutcome::Quarantined {
                    stage: EmergencyRecoveryStage::RecoveryRecordValidation,
                    reason: SupervisorRecoveryError::InvalidRecord,
                };
            }
        };
        record.state = SupervisorRecoveryState::EmergencyRecovery {
            payload,
            classification,
        };
        let outcome = self.recover_from_payload(record, worker_exit);
        match &outcome {
            SupervisorEmergencyRecoveryOutcome::Recovered { .. } => {
                info!(
                    pam_cleanup = "unavailable_after_worker_death",
                    "emergency session recovery complete"
                );
            }
            SupervisorEmergencyRecoveryOutcome::Quarantined { stage, reason } => {
                error!(
                    ?stage,
                    ?reason,
                    "emergency session recovery failed; seat quarantined"
                );
            }
        }
        outcome
    }

    pub(crate) fn recover_from_payload(
        &self,
        record: &mut SupervisorSessionRecoveryRecord,
        worker_exit: ExitStatus,
    ) -> SupervisorEmergencyRecoveryOutcome {
        let SupervisorRecoveryState::EmergencyRecovery { payload, .. } = &mut record.state else {
            return quarantine(
                EmergencyRecoveryStage::RecoveryRecordValidation,
                SupervisorRecoveryError::InvalidRecord,
            );
        };
        let proof = match payload
            .boundary
            .recover_emergency(worker_exit, EMERGENCY_BOUNDARY_TIMEOUT)
        {
            Ok(proof) => proof,
            Err(reason) => return quarantine(boundary_error_stage(&reason), reason),
        };
        info!("emergency payload boundary proof established");
        let unref_error = payload.boundary.release().err();
        if let Some(reason) = &unref_error {
            warn!(
                ?reason,
                "supervisor unit reference release failed after emergency empty proof"
            );
        }
        let logind_result = match self.provider.cleanup_logind(&payload.logind) {
            Ok(result) => result,
            Err(reason) => return quarantine(EmergencyRecoveryStage::LogindCleanup, reason),
        };
        if let Err(reason) = self.provider.recover_vt(&payload.vt) {
            let stage = if matches!(reason, SupervisorRecoveryError::SelinuxRestoreFailed(_)) {
                EmergencyRecoveryStage::SelinuxTtyRestore
            } else {
                EmergencyRecoveryStage::VtRecovery
            };
            return quarantine(stage, reason);
        }
        if let Some(reason) = unref_error {
            return quarantine(EmergencyRecoveryStage::SupervisorUnref, reason);
        }
        info!(worker_pid = record.worker_pid, worker_exit = %exit_status_label(worker_exit), "PAM cleanup unavailable after worker death");
        SupervisorEmergencyRecoveryOutcome::Recovered {
            containment_proof: SupervisorEmergencyContainmentProof::PayloadBoundary(proof),
            logind_result,
            pam_status: PamEmergencyCleanupStatus::UnavailableAfterWorkerDeath,
        }
    }
}

pub(crate) fn boundary_error_stage(reason: &SupervisorRecoveryError) -> EmergencyRecoveryStage {
    match reason {
        SupervisorRecoveryError::BusDeliveryIndeterminate => EmergencyRecoveryStage::EmergencyKill,
        SupervisorRecoveryError::BoundaryObserverUnavailable
        | SupervisorRecoveryError::BoundaryTimedOut => EmergencyRecoveryStage::BoundaryObservation,
        SupervisorRecoveryError::InvalidPayloadIdentity
        | SupervisorRecoveryError::BoundaryIdentityChanged
        | SupervisorRecoveryError::BusUnavailable => {
            EmergencyRecoveryStage::PayloadIdentityValidation
        }
        _ => EmergencyRecoveryStage::BoundaryProof,
    }
}

pub(crate) fn quarantine(
    stage: EmergencyRecoveryStage,
    reason: SupervisorRecoveryError,
) -> SupervisorEmergencyRecoveryOutcome {
    SupervisorEmergencyRecoveryOutcome::Quarantined { stage, reason }
}

pub(crate) fn classify_worker_exit(
    record: &SupervisorSessionRecoveryRecord,
    status: ExitStatus,
) -> WorkerExitClassification {
    use std::os::unix::process::ExitStatusExt;
    if let Some(signal) = status.signal() {
        return WorkerExitClassification::KilledBySignal(signal);
    }
    match (&record.state, status.success()) {
        (SupervisorRecoveryState::Started { .. }, true) => {
            WorkerExitClassification::CleanFinalization
        }
        (SupervisorRecoveryState::Started { .. }, false) => {
            WorkerExitClassification::UnexpectedExitRunning
        }
        (SupervisorRecoveryState::PayloadPrepared { .. }, _)
        | (SupervisorRecoveryState::PayloadRegistered { .. }, _) => {
            WorkerExitClassification::UnexpectedExitBeforeStarted
        }
        (SupervisorRecoveryState::PayloadReleased { .. }, _) => {
            WorkerExitClassification::FailedAfterBoundaryCleanup
        }
        (
            SupervisorRecoveryState::WorkerExitedUnexpectedly { classification, .. }
            | SupervisorRecoveryState::EmergencyRecovery { classification, .. },
            _,
        ) => *classification,
        _ => WorkerExitClassification::RecoveryGateLost,
    }
}
