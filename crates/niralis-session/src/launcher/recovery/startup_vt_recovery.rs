use super::*;

pub(crate) fn reconcile_startup_vt(
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
) -> Result<(), StartupRecoveryFailure> {
    let vt = persisted_vt_identity(record)?;
    match record.operation_ledger.vt_disallocate {
        DurableOperationState::Confirmed { .. } => return Ok(()),
        DurableOperationState::Failed { failure_class, .. } if failure_class == libc::EBUSY => {
            return Err(StartupRecoveryFailure::VtDisallocateBusy)
        }
        DurableOperationState::IntentPersisted { .. }
        | DurableOperationState::Failed { .. }
        | DurableOperationState::Indeterminate { .. } => {
            return Err(StartupRecoveryFailure::LogindIdentityChanged)
        }
        DurableOperationState::NotStarted => {}
    }
    let attempt = record.sequence.saturating_add(3);
    ledger
        .operation_intent(&record.lifecycle_id, "vt_disallocate", attempt)
        .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
    match recover_virtual_terminal(&vt) {
        Ok(()) => ledger
            .operation_confirmed(&record.lifecycle_id, "vt_disallocate", attempt)
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration),
        Err(SupervisorRecoveryError::VtDisallocateBusy) => {
            ledger
                .operation_failed(&record.lifecycle_id, "vt_disallocate", attempt, libc::EBUSY)
                .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
            Err(StartupRecoveryFailure::VtDisallocateBusy)
        }
        Err(_) => Err(StartupRecoveryFailure::LogindIdentityChanged),
    }
}

pub(crate) fn persisted_vt_identity(
    record: &PersistentRecoveryRecord,
) -> Result<SupervisorVtIdentity, StartupRecoveryFailure> {
    let target = record
        .target_vt
        .ok_or(StartupRecoveryFailure::LogindIdentityChanged)?;
    let previous = record
        .previous_vt
        .ok_or(StartupRecoveryFailure::LogindIdentityChanged)?;
    Ok(SupervisorVtIdentity {
        seat: record.seat.clone(),
        number: target,
        previous: PreviousVtIdentity { number: previous },
        device_major: 4,
        device_minor: target,
    })
}
