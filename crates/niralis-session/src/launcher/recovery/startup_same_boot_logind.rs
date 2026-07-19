use super::*;

pub(crate) fn reconcile_logind_and_vt(
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
    owner_watch: &OwnerWatch,
) -> Result<(), ()> {
    let owner = logind_owner().map_err(|_| ())?;
    let Some(id) = record
        .logind_session_id
        .as_deref()
        .and_then(|id| crate::LogindSessionId::new(id.to_owned()))
    else {
        return Err(());
    };
    if logind_session_exists(id.as_str()).map_err(|_| ())? {
        let identity = crate::PayloadScopeIdentity {
            unit_name: record.payload_unit.clone().ok_or(())?,
            invocation_id: record.invocation_id.clone().ok_or(())?,
            expected_uid: record.uid,
            logind_session_id: id.clone(),
        };
        let session = resolve_logind_identity(&identity).map_err(|_| ())?;
        if session.object_path != record.logind_object_path.clone().ok_or(())?
            || session.uid != record.uid
            || session.leader != record.worker_pid
            || session.seat != record.seat
            || Some(session.vt_number) != record.target_vt
        {
            return Err(());
        }
        owner_watch.stable().map_err(|_| ())?;
        let attempt = record.sequence.saturating_add(2);
        ledger
            .operation_intent(&record.lifecycle_id, "logind_termination", attempt)
            .map_err(|_| ())?;
        cleanup_logind_session(&session).map_err(|_| ())?;
        ledger
            .operation_confirmed(&record.lifecycle_id, "logind_termination", attempt)
            .map_err(|_| ())?;
    }
    if logind_owner().map_err(|_| ())? != owner || owner_watch.stable().is_err() {
        return Err(());
    }
    let target = record.target_vt.ok_or(())?;
    let previous = record.previous_vt.ok_or(())?;
    let attempt = record.sequence.saturating_add(3);
    ledger
        .operation_intent(&record.lifecycle_id, "vt_disallocate", attempt)
        .map_err(|_| ())?;
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
            .map_err(|_| ()),
        Err(SupervisorRecoveryError::VtDisallocateBusy) => {
            let _ = ledger.transition(&record.lifecycle_id, "vt_disallocate_failed_busy");
            Err(())
        }
        Err(_) => Err(()),
    }
}
