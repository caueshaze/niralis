use super::admin_support::{attempt, inspect_request, next_attempt_id, reject};
use super::*;
use crate::SessionError;

impl SupervisorLoopState {
    pub(super) fn recovery_admin(
        &mut self,
        request: crate::RecoveryAdminRequest,
    ) -> Result<crate::RecoveryAdminResponse, SessionError> {
        let Some(ledger) = &self.ledger else {
            return Ok(reject("persistent recovery is unavailable", None));
        };
        let mut ledger = ledger
            .lock()
            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
        match request {
            crate::RecoveryAdminRequest::InspectVt { seat, record_id } => {
                Ok(inspect_request(&ledger, seat, record_id))
            }
            crate::RecoveryAdminRequest::RetryVtDisallocate {
                seat,
                record_id,
                record_sequence,
                acknowledge_indeterminate,
            } => {
                let Some(record) = ledger.records.get(&record_id).cloned() else {
                    return Ok(reject("record does not exist", None));
                };
                if record.seat != seat || record.sequence != record_sequence {
                    return Ok(reject(
                        "record identity or sequence changed",
                        Some(record.sequence),
                    ));
                }
                if PersistentRecoveryLedger::boot_relation(&record)
                    != RecoveryBootRelation::SameBoot
                    || record.state != "quarantined"
                    || record.quarantine_reason.as_deref() != Some("vt_disallocate_busy")
                {
                    return Ok(reject(
                        "record is not an eligible VT busy quarantine",
                        Some(record.sequence),
                    ));
                }
                if ledger.records.values().any(|other| {
                    other.seat == seat
                        && other.lifecycle_id != record_id
                        && other.sequence >= record.sequence
                }) {
                    return Ok(reject(
                        "a newer record exists for this seat",
                        Some(record.sequence),
                    ));
                }
                if record.vt_busy_provenance.is_none() {
                    return Ok(reject("no durable busy provenance", Some(record.sequence)));
                }
                if let Some(previous) = record.vt_recovery_attempts.last() {
                    if matches!(previous.state, crate::VtRecoveryAttemptState::Indeterminate)
                        && acknowledge_indeterminate != Some(previous.attempt_id)
                    {
                        return Ok(reject(
                            "indeterminate attempt requires exact acknowledgement",
                            Some(record.sequence),
                        ));
                    }
                    if matches!(
                        previous.state,
                        crate::VtRecoveryAttemptState::IntentPersisted
                    ) {
                        return Ok(reject("previous administrative attempt is indeterminate and requires durable resolution", Some(record.sequence)));
                    }
                }
                if !matches!(
                    record.operation_ledger.payload_kill,
                    DurableOperationState::Confirmed { .. }
                ) || !matches!(
                    record.operation_ledger.supervisor_unref,
                    DurableOperationState::Confirmed { .. }
                ) {
                    return Ok(reject(
                        "payload boundary has not been durably finalized",
                        Some(record.sequence),
                    ));
                }
                if !self
                    .recovery_admin_host
                    .inspect_boundary(&record)
                    .is_absent()
                {
                    return Ok(reject(
                        "recovery boundary, worker, launcher, or logind session is not proven absent",
                        Some(record.sequence),
                    ));
                }
                let vt = match self.recovery_admin_host.persisted_vt_identity(&record) {
                    Ok(vt) => vt,
                    Err(_) => return Ok(reject("VT identity unavailable", Some(record.sequence))),
                };
                let provenance = self.recovery_admin_host.inspect_vt(&record, vt.number);
                if provenance.target_is_foreground != Some(false)
                    || !matches!(
                        provenance.classification,
                        crate::VtBusyClassification::KernelBusyUnattributed
                    )
                    || provenance.observed_active_vt != Some(vt.previous.number)
                {
                    let id = next_attempt_id(&record);
                    ledger
                        .append_vt_recovery_attempt(
                            &record_id,
                            attempt(
                                id,
                                record_sequence,
                                crate::VtRecoveryAttemptState::Rejected {
                                    reason: "VT preconditions changed".to_owned(),
                                },
                                provenance,
                                None,
                            ),
                        )
                        .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                    return Ok(reject(
                        "VT preconditions changed",
                        Some(record.sequence.saturating_add(1)),
                    ));
                }
                let id = next_attempt_id(&record);
                ledger
                    .append_vt_recovery_attempt(
                        &record_id,
                        attempt(
                            id,
                            record_sequence,
                            crate::VtRecoveryAttemptState::IntentPersisted,
                            provenance.clone(),
                            None,
                        ),
                    )
                    .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                match self.recovery_admin_host.disallocate_vt_once(vt.number) {
                    Ok(()) => {
                        let after = self.recovery_admin_host.inspect_vt(&record, vt.number);
                        if after.target_is_foreground != Some(false) {
                            ledger
                                .finish_vt_recovery_attempt(
                                    &record_id,
                                    id,
                                    crate::VtRecoveryAttemptState::Indeterminate,
                                    Some(after),
                                )
                                .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                            return Ok(reject("VT state changed after administrative ioctl", None));
                        }
                        ledger
                            .operation_confirmed(&record_id, "vt_disallocate", id)
                            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                        ledger
                            .finish_vt_recovery_attempt(
                                &record_id,
                                id,
                                crate::VtRecoveryAttemptState::Confirmed,
                                Some(after),
                            )
                            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                        ledger
                            .operation_confirmed(&record_id, "record_resolution", id)
                            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                        ledger
                            .mark_record_resolved(&record_id)
                            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                        if let Err(error) = self.recovery_admin_host.runtime_release(&record) {
                            ledger
                                .operation_failed(&record_id, "runtime_release", id, libc::EIO)
                                .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                            return Ok(reject(&format!("runtime release failed: {error:?}"), None));
                        }
                        ledger
                            .operation_confirmed(&record_id, "runtime_release", id)
                            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                        ledger
                            .remove_resolved(&record_id)
                            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                        self.seat = SeatLifecycle::Free;
                        Ok(crate::RecoveryAdminResponse::RetryAccepted {
                            record_id,
                            sequence: record_sequence.saturating_add(3),
                            attempt_id: id,
                        })
                    }
                    Err(SupervisorRecoveryError::VtDisallocateBusy) => {
                        let after = self.recovery_admin_host.inspect_vt(&record, vt.number);
                        ledger
                            .finish_vt_recovery_attempt(
                                &record_id,
                                id,
                                crate::VtRecoveryAttemptState::Failed { errno: libc::EBUSY },
                                Some(after.clone()),
                            )
                            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                        ledger
                            .record_vt_busy_provenance(&record_id, after)
                            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                        Ok(crate::RecoveryAdminResponse::RetryAccepted {
                            record_id,
                            sequence: record_sequence.saturating_add(2),
                            attempt_id: id,
                        })
                    }
                    Err(error) => {
                        let errno = match error {
                            SupervisorRecoveryError::VtDisallocateFailed(errno) => errno,
                            _ => libc::EIO,
                        };
                        ledger
                            .finish_vt_recovery_attempt(
                                &record_id,
                                id,
                                crate::VtRecoveryAttemptState::Failed { errno },
                                None,
                            )
                            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
                        Ok(reject(&format!("VT retry failed: {error:?}"), None))
                    }
                }
            }
        }
    }
}
