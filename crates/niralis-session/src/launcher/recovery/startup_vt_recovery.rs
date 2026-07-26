use super::*;

pub(crate) fn reconcile_startup_vt(
    snapshot: RecoveryStateSnapshot,
    ledger: &mut PersistentRecoveryLedger,
    boundary_proof: Option<AuthorizedRecoveryBoundaryProof>,
    owner_watch: &OwnerWatch,
) -> Result<(), StartupRecoveryFailure> {
    let record = &snapshot.record;
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
    let proof = boundary_proof.ok_or(StartupRecoveryFailure::BoundaryIdentityChanged)?;
    let owner = owner_watch
        .stable_snapshot()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    let _validated =
        ValidatedRecoveryVtTarget::from_identity(&snapshot, vt.clone(), &proof, &owner)
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    let (next_snapshot, permit) = ledger
        .persist_recovery_intent_from_snapshot::<VtRecoveryOperation>(
            snapshot,
            "vt_disallocate",
            attempt,
        )
        .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
    let authorized = proof.authorize_next_sequence(next_snapshot.record.sequence);
    let target =
        ValidatedRecoveryVtTarget::from_identity(&next_snapshot, vt.clone(), &authorized, &owner)
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    match SameBootVtEffects::recover(
        &next_snapshot.authority,
        target,
        &authorized,
        permit,
        owner_watch,
        &owner,
    ) {
        Ok(()) => ledger
            .operation_confirmed(
                &next_snapshot.record.lifecycle_id,
                "vt_disallocate",
                attempt,
            )
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration),
        Err(SupervisorRecoveryError::VtDisallocateBusy) => {
            ledger
                .operation_failed(
                    &next_snapshot.record.lifecycle_id,
                    "vt_disallocate",
                    attempt,
                    libc::EBUSY,
                )
                .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
            let provenance = inspect_vt_busy(
                vt.number,
                &[
                    VtKnownProcess {
                        pid: std::process::id(),
                        starttime: None,
                    },
                    VtKnownProcess {
                        pid: next_snapshot.record.worker_pid,
                        starttime: next_snapshot.record.worker_starttime,
                    },
                    VtKnownProcess {
                        pid: next_snapshot.record.launcher_pid,
                        starttime: None,
                    },
                    VtKnownProcess {
                        pid: next_snapshot.record.leader_pid.unwrap_or(0),
                        starttime: next_snapshot.record.leader_starttime,
                    },
                ],
            );
            ledger
                .record_vt_busy_provenance(&next_snapshot.record.lifecycle_id, provenance)
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
