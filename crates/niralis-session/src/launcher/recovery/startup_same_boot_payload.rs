use super::*;

pub(crate) fn reconcile_payload(
    mut snapshot: RecoveryStateSnapshot,
    pin: &mut RecoveryPinnedInvocationUnit,
    leader: &PersistedProcessIdentity,
    ledger: &mut PersistentRecoveryLedger,
    owner_watch: &OwnerWatch,
) -> Result<(RecoveryStateSnapshot, RecoveryBoundaryEmptyProof), StartupRecoveryFailure> {
    let record = &snapshot.record;
    if matches!(
        pin.boundary_state()
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?,
        SupervisorBoundaryState::Populated
    ) {
        let owner_authority = owner_watch
            .stable_snapshot()
            .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
        if matches!(
            record.operation_ledger.payload_kill,
            DurableOperationState::IntentPersisted { .. }
                | DurableOperationState::Indeterminate { .. }
        ) {
            return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
        }
        let attempt = record.sequence.saturating_add(1);
        let (next_snapshot, kill_permit) = ledger
            .persist_recovery_intent_from_snapshot::<PayloadKillOperation>(
                snapshot,
                "payload_kill",
                attempt,
            )
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
        pin.rebind(&next_snapshot.authority, &next_snapshot.record)
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
        pin.request_recovery_emergency_kill(
            &next_snapshot.authority,
            &next_snapshot.record,
            kill_permit,
        )
        .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
        owner_watch
            .still_authorizes(&owner_authority)
            .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
        wait_for_boundary_empty(pin, owner_watch, &owner_authority)?;
        ledger
            .operation_confirmed(&next_snapshot.record.lifecycle_id, "payload_kill", attempt)
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
        snapshot = ledger
            .refresh_recovery_snapshot(next_snapshot)
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
        pin.rebind(&snapshot.authority, &snapshot.record)
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    }
    if matches!(leader, PersistedProcessIdentity::OriginalStillAlive { .. }) {
        return Err(StartupRecoveryFailure::LeaderIdentityIndeterminate);
    }
    let proof_authority = owner_watch
        .stable_snapshot()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    let proof = startup_boundary_proof(pin, owner_watch, &proof_authority, &snapshot)?;
    Ok((snapshot, proof))
}
