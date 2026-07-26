use super::*;

pub(super) fn next_operation_attempt_id(
    record: &PersistentRecoveryRecord,
) -> Result<u64, PreviousBootFinalizationError> {
    [
        record.operation_ledger.payload_kill,
        record.operation_ledger.supervisor_unref,
        record.operation_ledger.logind_termination,
        record.operation_ledger.selinux_restore,
        record.operation_ledger.vt_activation,
        record.operation_ledger.vt_disallocate,
        record.operation_ledger.record_resolution,
        record.operation_ledger.runtime_release,
    ]
    .into_iter()
    .filter_map(|state| match state {
        DurableOperationState::NotStarted => None,
        DurableOperationState::IntentPersisted { attempt_id }
        | DurableOperationState::Confirmed { attempt_id }
        | DurableOperationState::Failed { attempt_id, .. }
        | DurableOperationState::Indeterminate { attempt_id, .. } => Some(attempt_id),
    })
    .max()
    .unwrap_or(0)
    .checked_add(1)
    .ok_or(PreviousBootFinalizationError::Conflicted)
}
