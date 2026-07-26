use super::vt_verification::{inspect_startup_virtual_terminal, StartupVtRecoveryState};
use super::*;

pub(crate) fn reconcile_logind_and_vt(
    mut snapshot: RecoveryStateSnapshot,
    ledger: &mut PersistentRecoveryLedger,
    owner_watch: &OwnerWatch,
    boundary_proof: Option<AuthorizedRecoveryBoundaryProof>,
) -> Result<(), StartupRecoveryFailure> {
    let authority = owner_watch
        .stable_snapshot()
        .map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
    let owner = logind_owner().map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
    let record = &snapshot.record;
    let Some(id) = record
        .logind_session_id
        .as_deref()
        .and_then(|id| crate::LogindSessionId::new(id.to_owned()))
    else {
        return Err(StartupRecoveryFailure::LogindIdentityChanged);
    };
    if logind_session_exists(id.as_str()).map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)? {
        let identity = crate::PayloadScopeIdentity {
            unit_name: record
                .payload_unit
                .clone()
                .ok_or(StartupRecoveryFailure::LogindIdentityChanged)?,
            invocation_id: record
                .invocation_id
                .clone()
                .ok_or(StartupRecoveryFailure::LogindIdentityChanged)?,
            expected_uid: record.uid,
            logind_session_id: id.clone(),
        };
        let session = resolve_logind_identity(&identity)
            .map_err(|_| StartupRecoveryFailure::LogindIdentityChanged)?;
        if session.object_path
            != record
                .logind_object_path
                .clone()
                .ok_or(StartupRecoveryFailure::LogindIdentityChanged)?
            || session.uid != record.uid
            || session.leader != record.worker_pid
            || session.seat != record.seat
            || Some(session.vt_number) != record.target_vt
        {
            return Err(StartupRecoveryFailure::LogindIdentityChanged);
        }
        let validated =
            ValidatedRecoveryLogindSession::from_identity(&snapshot, session.clone(), &authority)
                .map_err(|_| StartupRecoveryFailure::LogindIdentityChanged)?;
        owner_watch
            .still_authorizes(&authority)
            .map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
        let attempt = record.sequence.saturating_add(2);
        let (next_snapshot, permit) = ledger
            .persist_recovery_intent_from_snapshot::<LogindCleanupOperation>(
                snapshot,
                "logind_termination",
                attempt,
            )
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
        let target = ValidatedRecoveryLogindSession::from_identity(
            &next_snapshot,
            validated.as_identity(),
            &authority,
        )
        .map_err(|_| StartupRecoveryFailure::LogindIdentityChanged)?;
        SameBootLogindEffects::terminate_session(
            &next_snapshot.authority,
            target,
            permit,
            owner_watch,
            &authority,
        )
        .map_err(|error| match error {
            SupervisorRecoveryError::LogindCleanupIndeterminate => {
                StartupRecoveryFailure::LogindOwnerChanged
            }
            SupervisorRecoveryError::LogindOwnerChanged => {
                StartupRecoveryFailure::LogindOwnerChanged
            }
            _ => StartupRecoveryFailure::LogindIdentityChanged,
        })?;
        // Never classify a call whose owner changed while it was in flight as
        // removed or already gone.  The durable intent is intentionally left
        // unconfirmed, so a later daemon cannot repeat it automatically.
        owner_watch
            .still_authorizes(&authority)
            .map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
        ledger
            .operation_confirmed(
                &next_snapshot.record.lifecycle_id,
                "logind_termination",
                attempt,
            )
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
        snapshot = ledger
            .refresh_recovery_snapshot(next_snapshot)
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
    }
    if logind_owner().map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)? != owner
        || owner_watch.still_authorizes(&authority).is_err()
    {
        return Err(StartupRecoveryFailure::LogindOwnerChanged);
    }
    reconcile_startup_vt(snapshot, ledger, boundary_proof, owner_watch)
}

pub(crate) fn confirm_absent_boundary_logind_and_vt(
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
    owner_watch: &OwnerWatch,
) -> Result<(), StartupRecoveryFailure> {
    let authority = owner_watch
        .stable_snapshot()
        .map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
    let owner = logind_owner().map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
    let id = record
        .logind_session_id
        .as_deref()
        .ok_or(StartupRecoveryFailure::LogindIdentityChanged)?;
    if logind_session_exists(id).map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)? {
        return Err(StartupRecoveryFailure::LogindIdentityChanged);
    }
    owner_watch
        .still_authorizes(&authority)
        .map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
    if logind_owner().map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)? != owner {
        return Err(StartupRecoveryFailure::LogindOwnerChanged);
    }
    let vt = persisted_vt_identity(record)?;
    match inspect_startup_virtual_terminal(&vt)
        .map_err(|_| StartupRecoveryFailure::LogindIdentityChanged)?
    {
        StartupVtRecoveryState::Recovered => confirm_default_tty_context(record, ledger, &vt)?,
        StartupVtRecoveryState::NeedsRecovery => {
            info!(
                lifecycle_id = %record.lifecycle_id,
                target_vt = vt.number,
                "startup absent-boundary VT remains allocated; resuming supervisor VT recovery"
            );
            let current_boot = BootIdentity::parse(
                current_boot_id().map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?,
            )
            .map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
            let snapshot = RecoveryStateSnapshot::from_record(&current_boot, record.clone())
                .map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
            let proof = RecoveryBoundaryEmptyProof::from_absent_boundary(&snapshot)
                .authorize(snapshot.record.sequence);
            reconcile_startup_vt(snapshot, ledger, Some(proof), owner_watch)?;
        }
    }
    owner_watch
        .still_authorizes(&authority)
        .map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
    if logind_owner().map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)? != owner {
        return Err(StartupRecoveryFailure::LogindOwnerChanged);
    }
    info!(
        lifecycle_id = %record.lifecycle_id,
        target_vt = vt.number,
        previous_vt = vt.previous.number,
        "startup absent-boundary logind and VT recovery confirmed"
    );
    Ok(())
}

fn confirm_default_tty_context(
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
    vt: &SupervisorVtIdentity,
) -> Result<(), StartupRecoveryFailure> {
    match record.operation_ledger.selinux_restore {
        DurableOperationState::NotStarted => {
            let attempt = record.sequence.saturating_add(1);
            ledger
                .operation_intent(&record.lifecycle_id, "selinux_restore", attempt)
                .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
            let path = CString::new(format!("/dev/tty{}", vt.number))
                .map_err(|_| StartupRecoveryFailure::LogindIdentityChanged)?;
            restore_default_selinux_context(&path)
                .map_err(|_| StartupRecoveryFailure::LogindIdentityChanged)?;
            ledger
                .operation_confirmed(&record.lifecycle_id, "selinux_restore", attempt)
                .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)
        }
        DurableOperationState::Confirmed { .. } => Ok(()),
        DurableOperationState::IntentPersisted { .. }
        | DurableOperationState::Failed { .. }
        | DurableOperationState::Indeterminate { .. } => {
            Err(StartupRecoveryFailure::LogindIdentityChanged)
        }
    }
}
