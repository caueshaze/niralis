use super::*;

pub(crate) fn quarantine_startup_record(
    ledger: &mut PersistentRecoveryLedger,
    lifecycle_id: &str,
    reason: StartupRecoveryFailure,
    summary: &mut StartupReconciliationSummary,
) {
    if ledger.records().any(|record| {
        record.lifecycle_id == lifecycle_id
            && record.state == "quarantined"
            && record.quarantine_reason.as_deref() == Some(reason.persistent_reason())
    }) {
        summary.quarantined += 1;
        return;
    }
    if ledger.quarantine(lifecycle_id, reason).is_err() {
        ledger.mark_startup_quarantine();
        warn!(
            lifecycle_id,
            reason = reason.persistent_reason(),
            "failed to persist startup quarantine"
        );
    } else {
        info!(
            lifecycle_id,
            reason = reason.persistent_reason(),
            "startup quarantine persisted"
        );
    }
    summary.quarantined += 1;
}

pub(crate) fn can_retry_coherent_absent_boundary(record: &PersistentRecoveryRecord) -> bool {
    record.state == "quarantined"
        && record.quarantine_reason.as_deref() == Some("boundary_identity_changed")
        && matches!(
            record.operation_ledger,
            DurableOperationLedger {
                payload_kill: DurableOperationState::NotStarted,
                supervisor_unref: DurableOperationState::NotStarted,
                logind_termination: DurableOperationState::NotStarted,
                selinux_restore: DurableOperationState::NotStarted,
                vt_activation: DurableOperationState::NotStarted,
                vt_disallocate: DurableOperationState::NotStarted,
                runtime_release: DurableOperationState::NotStarted,
                record_resolution: DurableOperationState::NotStarted,
            }
        )
}
