use super::*;
use tracing::{info, warn};

impl SupervisorLoopState {
    pub(super) fn begin_release(
        &mut self,
        request: ReleaseRequest,
    ) -> Result<ReleaseToken, SessionError> {
        let entry = self
            .pending
            .iter_mut()
            .find(|entry| {
                entry.record.lifecycle_id == request.worker_id
                    && entry.record.worker_pid == request.worker_pid
            })
            .filter(|entry| {
                !entry.terminal_before_started
                    && entry.record.payload_identity() == Some(&request.identity)
                    && registration_nonce(&entry.record) == Some(request.registration_nonce.as_str())
                    && (matches!(&entry.release, PendingReleaseState::NotRequested)
                        || matches!(&entry.release, PendingReleaseState::Requested { nonce } if nonce == &request.release_nonce))
            })
            .ok_or(SessionError::WorkerProtocolFailed)?;
        entry.release = PendingReleaseState::Requested {
            nonce: request.release_nonce.clone(),
        };
        entry.generation = entry.generation.wrapping_add(1);
        Ok(ReleaseToken {
            worker_id: request.worker_id,
            worker_pid: request.worker_pid,
            registration_nonce: request.registration_nonce,
            release_nonce: request.release_nonce,
            identity: request.identity,
            generation: entry.generation,
        })
    }

    pub(super) fn complete_release(
        &mut self,
        token: ReleaseToken,
        verification: crate::ScopeReleaseVerification,
    ) -> Result<(), SessionError> {
        let entry = self
            .pending
            .iter_mut()
            .find(|entry| {
                entry.record.lifecycle_id == token.worker_id
                    && entry.record.worker_pid == token.worker_pid
                    && entry.generation == token.generation
                    && entry.record.payload_identity() == Some(&token.identity)
                    && registration_nonce(&entry.record) == Some(token.registration_nonce.as_str())
                    && matches!(&entry.release, PendingReleaseState::Requested { nonce } if nonce == &token.release_nonce)
            })
            .ok_or(SessionError::WorkerProtocolFailed)?;
        match verification {
            crate::ScopeReleaseVerification::Released => {
                let state = entry.record.take_state_for_transition();
                let payload = match state {
                    SupervisorRecoveryState::PayloadPrepared { payload, .. }
                    | SupervisorRecoveryState::PayloadRegistered { payload, .. } => payload,
                    state => {
                        entry.record.state = state;
                        return Err(SessionError::WorkerProtocolFailed);
                    }
                };
                entry.record.state = SupervisorRecoveryState::PayloadReleased { payload };
                Ok(())
            }
            crate::ScopeReleaseVerification::RecoveryRequired(reason) => {
                entry.release = PendingReleaseState::RecoveryRequired(reason);
                entry.terminal_before_started = true;
                Ok(())
            }
        }
    }

    pub(super) fn abort_pending(
        &mut self,
        worker_id: String,
        expected_clean: bool,
        worker_exit_status: Option<ExitStatus>,
    ) -> Result<(), SessionError> {
        let Some(index) = self
            .pending
            .iter()
            .position(|entry| entry.record.lifecycle_id == worker_id)
        else {
            return Ok(());
        };
        let mut entry = self.pending.swap_remove(index);
        if let PendingReleaseState::RecoveryRequired(reason) = &entry.release {
            warn!(
                ?reason,
                worker_id, "pre-Started release verification requires supervisor recovery"
            );
        }
        let status = worker_exit_status
            .map(Ok)
            .unwrap_or_else(|| reap_pending_worker(&entry.child))?;
        let expected_cleanup_verified = expected_clean
            && if entry.record.payload_identity().is_none() {
                true
            } else {
                finalize_expected_prestarted_exit(
                    &mut entry.record,
                    status,
                    self.recovery_provider.as_ref(),
                )
                .is_ok()
            };
        if expected_cleanup_verified {
            self.seat = SeatLifecycle::Free;
            return Ok(());
        }
        if entry.record.payload_identity().is_some() {
            warn!(worker_id, status = %exit_status_label(status), "worker died with supervisor-owned payload recovery record retained");
            self.recover_payload_entry(entry, status)
        } else {
            self.recover_pre_payload_entry(entry, status)
        }
    }

    pub(super) fn recover_payload_entry(
        &mut self,
        mut entry: PendingWorkerLifecycle,
        status: ExitStatus,
    ) -> Result<(), SessionError> {
        let classification = mark_worker_exited_unexpectedly(&mut entry.record, status);
        self.seat = SeatLifecycle::Recovering {
            lifecycle_id: entry.record.lifecycle_id.clone(),
            phase: entry.record.phase_name(),
            reason: classification,
        };
        match SupervisorEmergencyRecoveryCoordinator::new(self.recovery_provider.as_ref())
            .recover(&mut entry.record, status)
        {
            outcome @ SupervisorEmergencyRecoveryOutcome::Recovered { .. } => {
                entry.record.state = SupervisorRecoveryState::Recovered { outcome };
                self.seat = SeatLifecycle::Free;
                Ok(())
            }
            SupervisorEmergencyRecoveryOutcome::Quarantined { stage, reason } => {
                entry.record.quarantine(stage, reason.clone());
                self.seat = SeatLifecycle::Quarantined {
                    lifecycle_id: entry.record.lifecycle_id.clone(),
                    stage,
                    reason,
                };
                self.quarantined.push(entry.record);
                Err(SessionError::WorkerRecoveryIncomplete)
            }
        }
    }

    pub(super) fn recover_pre_payload_entry(
        &mut self,
        mut entry: PendingWorkerLifecycle,
        status: ExitStatus,
    ) -> Result<(), SessionError> {
        let previous_vt = match &entry.record.state {
            SupervisorRecoveryState::WorkerSpawned { previous_vt } => previous_vt.clone(),
            _ => {
                return self.quarantine_pre_payload(
                    entry,
                    EmergencyRecoveryStage::RecoveryRecordValidation,
                    SupervisorRecoveryError::InvalidRecord,
                )
            }
        };
        info!(lifecycle_id = %entry.record.lifecycle_id, "starting emergency supervisor recovery before payload registration");
        match self.recovery_provider.recover_pre_payload(
            entry.record.worker_pid,
            &entry.record.requested_username,
            &entry.record.session_name,
            &previous_vt,
        ) {
            Ok(pre_payload) => {
                info!(worker_pid = entry.record.worker_pid, worker_exit = %exit_status_label(status), "PAM cleanup unavailable after worker death");
                entry.record.state = SupervisorRecoveryState::Recovered {
                    outcome: SupervisorEmergencyRecoveryOutcome::Recovered {
                        containment_proof:
                            SupervisorEmergencyContainmentProof::NoPayloadScopeWasRegistered {
                                worker_exit: exit_status_label(status),
                            },
                        logind_result: pre_payload.logind_result,
                        pam_status: PamEmergencyCleanupStatus::UnavailableAfterWorkerDeath,
                    },
                };
                self.seat = SeatLifecycle::Free;
                Ok(())
            }
            Err(reason) => {
                self.quarantine_pre_payload(entry, EmergencyRecoveryStage::LogindCleanup, reason)
            }
        }
    }

    pub(super) fn quarantine_pre_payload(
        &mut self,
        mut entry: PendingWorkerLifecycle,
        stage: EmergencyRecoveryStage,
        reason: SupervisorRecoveryError,
    ) -> Result<(), SessionError> {
        entry.record.quarantine(stage, reason.clone());
        self.seat = SeatLifecycle::Quarantined {
            lifecycle_id: entry.record.lifecycle_id.clone(),
            stage,
            reason,
        };
        self.quarantined.push(entry.record);
        Err(SessionError::WorkerRecoveryIncomplete)
    }
}
