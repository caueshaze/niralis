use super::*;

pub(crate) fn reconcile_logind_and_vt(
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
    owner_watch: &OwnerWatch,
) -> Result<(), StartupRecoveryFailure> {
    let owner = logind_owner().map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
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
        owner_watch
            .stable()
            .map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)?;
        let attempt = record.sequence.saturating_add(2);
        ledger
            .operation_intent(&record.lifecycle_id, "logind_termination", attempt)
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
        cleanup_logind_session(&session)
            .map_err(|_| StartupRecoveryFailure::LogindIdentityChanged)?;
        ledger
            .operation_confirmed(&record.lifecycle_id, "logind_termination", attempt)
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
    }
    if logind_owner().map_err(|_| StartupRecoveryFailure::LogindOwnerChanged)? != owner
        || owner_watch.stable().is_err()
    {
        return Err(StartupRecoveryFailure::LogindOwnerChanged);
    }
    let target = record
        .target_vt
        .ok_or(StartupRecoveryFailure::LogindIdentityChanged)?;
    let previous = record
        .previous_vt
        .ok_or(StartupRecoveryFailure::LogindIdentityChanged)?;
    let attempt = record.sequence.saturating_add(3);
    ledger
        .operation_intent(&record.lifecycle_id, "vt_disallocate", attempt)
        .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
    let vt = SupervisorVtIdentity {
        seat: record.seat.clone(),
        number: target,
        previous: PreviousVtIdentity { number: previous },
        device_major: 4,
        device_minor: target,
    };
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
