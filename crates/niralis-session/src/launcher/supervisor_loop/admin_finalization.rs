use super::*;

pub(super) fn finalize_admin_success(
    host: &RecoveryAdminHostRef,
    admission: &mut SeatAdmissionController,
    ledger: &mut PersistentRecoveryLedger,
    record_id: &str,
    attempt_id: u64,
) -> Result<(), String> {
    let record = ledger
        .records
        .get(record_id)
        .cloned()
        .ok_or_else(|| "recovery record disappeared".to_owned())?;
    let boot = BootIdentity::parse(record.created_boot_id.clone())
        .map_err(|_| "invalid recovery boot identity".to_owned())?;
    let snapshot = RecoveryStateSnapshot::from_record(&boot, record)
        .map_err(|_| "stale recovery authority".to_owned())?;
    let completion = FinalizationCompletionProof::from_snapshot(&snapshot)
        .map_err(|_| "invalid completion proof".to_owned())?;
    let (resolved_snapshot, resolved, runtime_permit) = ledger
        .mark_record_resolved_typed(snapshot, completion)
        .map_err(|_| "could not persist RecordResolved".to_owned())?;
    if let Err(error) = host.runtime_release(&resolved_snapshot.record) {
        ledger
            .operation_failed(record_id, "runtime_release", attempt_id, libc::EIO)
            .map_err(|_| "could not persist runtime release failure".to_owned())?;
        return Err(format!("runtime release failed: {error:?}"));
    }
    let (released_snapshot, resolved, confirmed, removal_permit) = ledger
        .confirm_runtime_release_typed(resolved_snapshot, resolved, runtime_permit)
        .map_err(|_| "could not persist runtime release confirmation".to_owned())?;
    let removed = ledger
        .remove_record_typed(released_snapshot, resolved, confirmed, removal_permit)
        .map_err(|_| "could not remove the exact resolved record".to_owned())?;
    let admin_receipt = admission
        .issue_admin_finalization_receipt(&removed)
        .map_err(|_| "seat authority changed before finalization receipt".to_owned())?;
    let free_permit = ledger
        .issue_seat_free_permit(removed)
        .map_err(|_| "seat free preconditions changed".to_owned())?;
    ledger
        .consume_seat_free_permit(free_permit)
        .map_err(|_| "seat free preconditions changed".to_owned())?;
    admission
        .release_after_admin_finalization(admin_receipt)
        .map_err(|_| "seat authority changed before publication".to_owned())?;
    Ok(())
}
