use super::*;

pub(super) fn reject(reason: &str, sequence: Option<u64>) -> crate::RecoveryAdminResponse {
    crate::RecoveryAdminResponse::Rejected {
        reason: reason.to_owned(),
        sequence,
    }
}

pub(super) fn operation_ledger(ledger: &DurableOperationLedger) -> crate::RecoveryOperationLedger {
    crate::RecoveryOperationLedger {
        payload_kill: operation_state(ledger.payload_kill),
        supervisor_unref: operation_state(ledger.supervisor_unref),
        logind_termination: operation_state(ledger.logind_termination),
        selinux_restore: operation_state(ledger.selinux_restore),
        vt_activation: operation_state(ledger.vt_activation),
        vt_disallocate: operation_state(ledger.vt_disallocate),
        runtime_release: operation_state(ledger.runtime_release),
        record_resolution: operation_state(ledger.record_resolution),
    }
}

pub(super) fn inspection(record: PersistentRecoveryRecord) -> crate::RecoveryAdminResponse {
    crate::RecoveryAdminResponse::Inspection(Box::new(crate::RecoveryVtInspection {
        seat: record.seat,
        record_id: record.lifecycle_id,
        sequence: record.sequence,
        target_vt: record.target_vt.unwrap_or(0),
        quarantine_reason: record.quarantine_reason,
        operation_ledger: operation_ledger(&record.operation_ledger),
        provenance: record.vt_busy_provenance,
        attempts: record.vt_recovery_attempts,
    }))
}

pub(super) fn inspect_request(
    ledger: &PersistentRecoveryLedger,
    seat: String,
    record_id: String,
) -> crate::RecoveryAdminResponse {
    let Some(record) = ledger.records.get(&record_id).cloned() else {
        return reject("record does not exist", None);
    };
    if record.seat != seat {
        return reject("seat does not match record", Some(record.sequence));
    }
    inspection(record)
}

fn operation_state(state: DurableOperationState) -> crate::RecoveryOperationState {
    match state {
        DurableOperationState::NotStarted => crate::RecoveryOperationState::NotStarted,
        DurableOperationState::IntentPersisted { attempt_id } => {
            crate::RecoveryOperationState::IntentPersisted { attempt_id }
        }
        DurableOperationState::Confirmed { attempt_id } => {
            crate::RecoveryOperationState::Confirmed { attempt_id }
        }
        DurableOperationState::Failed {
            attempt_id,
            failure_class,
        } => crate::RecoveryOperationState::Failed {
            attempt_id,
            failure_class,
        },
        DurableOperationState::Indeterminate { attempt_id, stage } => {
            crate::RecoveryOperationState::Indeterminate { attempt_id, stage }
        }
    }
}

pub(super) fn next_attempt_id(record: &PersistentRecoveryRecord) -> u64 {
    record
        .vt_recovery_attempts
        .iter()
        .map(|attempt| attempt.attempt_id)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

pub(super) fn attempt(
    id: u64,
    sequence: u64,
    state: crate::VtRecoveryAttemptState,
    before: crate::VtBusyProvenance,
    after: Option<crate::VtBusyProvenance>,
) -> crate::VtRecoveryAttempt {
    crate::VtRecoveryAttempt {
        attempt_id: id,
        requested_by: 0,
        expected_sequence: sequence,
        state,
        provenance_before: before,
        provenance_after: after,
    }
}
