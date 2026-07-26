use super::*;

impl PreviousBootFinalizationAuthority {
    pub(super) fn from_record(
        record: &PreviousBootRecoveryRecord,
        fingerprint: String,
        file: RecordFileIdentity,
    ) -> Result<Self, PreviousBootFinalizationError> {
        if record.recorded_boot == record.current_boot {
            return Err(PreviousBootFinalizationError::StaleSnapshot);
        }
        Ok(Self {
            current_boot: record.current_boot.clone(),
            recorded_boot: record.recorded_boot.clone(),
            record_id: record.record.lifecycle_id.clone(),
            lifecycle_id: record.record.lifecycle_id.clone(),
            seat: record.record.seat.clone(),
            sequence: record.record.sequence,
            fingerprint,
            file,
        })
    }

    pub(super) fn validates(
        &self,
        record: &PersistentRecoveryRecord,
        current: &BootIdentity,
        file: &RecordFileIdentity,
    ) -> bool {
        self.current_boot == *current
            && self.recorded_boot.as_str() == record.created_boot_id
            && self.record_id == record.lifecycle_id
            && self.lifecycle_id == record.lifecycle_id
            && self.seat == record.seat
            && self.sequence == record.sequence
            && self.file == *file
    }

    pub(super) fn clone_for_transition(&self) -> Self {
        Self {
            current_boot: self.current_boot.clone(),
            recorded_boot: self.recorded_boot.clone(),
            record_id: self.record_id.clone(),
            lifecycle_id: self.lifecycle_id.clone(),
            seat: self.seat.clone(),
            sequence: self.sequence,
            fingerprint: self.fingerprint.clone(),
            file: RecordFileIdentity {
                device: self.file.device,
                inode: self.file.inode,
                links: self.file.links,
            },
        }
    }
}

pub(super) fn fingerprint(
    record: &PreviousBootRecoveryRecord,
    facts: &PreviousBootCurrentFacts,
    plan: &PreviousBootRecoveryPlan,
) -> String {
    format!(
        "{}:{}:{plan:?}:{facts:?}",
        record.record.lifecycle_id, record.record.sequence
    )
}

pub(super) fn current_record(
    ledger: &PersistentRecoveryLedger,
    id: &str,
) -> Result<PersistentRecoveryRecord, PreviousBootFinalizationError> {
    ledger
        .records()
        .find(|record| record.lifecycle_id == id)
        .cloned()
        .ok_or(PreviousBootFinalizationError::StaleSnapshot)
}

pub(super) fn revalidate(
    ledger: &PersistentRecoveryLedger,
    host: &dyn PreviousBootInspectionHost,
    original: &PreviousBootRecoveryRecord,
    facts: &PreviousBootCurrentFacts,
    plan: &PreviousBootRecoveryPlan,
    expected_file: &RecordFileIdentity,
) -> Result<PreviousBootFinalizationAuthority, PreviousBootFinalizationError> {
    let current_boot = host
        .current_boot_identity()
        .map_err(|_| PreviousBootFinalizationError::StaleSnapshot)?;
    if current_boot != original.current_boot {
        return Err(PreviousBootFinalizationError::StaleSnapshot);
    }
    let current = current_record(ledger, &original.record.lifecycle_id)?;
    let current_file = ledger.record_file_identity(&original.record.lifecycle_id)?;
    if current_file != *expected_file {
        return Err(PreviousBootFinalizationError::StaleSnapshot);
    }
    let current_epoch = RecoveryRecordEpoch::classify(current.clone(), current_boot.clone())
        .map_err(|_| PreviousBootFinalizationError::StaleSnapshot)?;
    let RecoveryRecordEpoch::PreviousBoot(current_previous) = current_epoch else {
        return Err(PreviousBootFinalizationError::Conflicted);
    };
    let current_facts = host
        .inspect_current_snapshot(&PreviousBootInspectionRequest {
            record: current_previous.clone(),
            records: ledger.records().cloned().collect(),
        })
        .map_err(|_| PreviousBootFinalizationError::StaleSnapshot)?;
    let current_plan = plan_previous_boot_reconciliation(&current_previous, &current_facts);
    if fingerprint(original, facts, plan)
        != fingerprint(&current_previous, &current_facts, &current_plan)
        || !current_facts.authority.stable
    {
        return Err(PreviousBootFinalizationError::PlanChanged);
    }
    let authority = PreviousBootFinalizationAuthority::from_record(
        &current_previous,
        fingerprint(&current_previous, &current_facts, &current_plan),
        current_file,
    )?;
    if authority.sequence != current.sequence {
        return Err(PreviousBootFinalizationError::StaleSnapshot);
    }
    Ok(authority)
}

pub(super) fn advance(
    ledger: &mut PersistentRecoveryLedger,
    authority: &PreviousBootFinalizationAuthority,
    state: &str,
) -> Result<PreviousBootFinalizationAuthority, PreviousBootFinalizationError> {
    let current = current_record(ledger, &authority.record_id)?;
    let file = ledger.record_file_identity(&authority.record_id)?;
    if !authority.validates(&current, &authority.current_boot, &file) {
        return Err(PreviousBootFinalizationError::StaleSnapshot);
    }
    match state {
        "previous_boot_resolution_intent" => ledger.transition_with_operation(
            &authority.record_id,
            state,
            "record_resolution",
            DurableOperationState::IntentPersisted {
                attempt_id: authority.sequence.saturating_add(1),
            },
        )?,
        "record_resolved" => {
            let attempt_id = match current.operation_ledger.record_resolution {
                DurableOperationState::IntentPersisted { attempt_id } => attempt_id,
                DurableOperationState::NotStarted => authority.sequence.saturating_add(1),
                DurableOperationState::Confirmed { .. } => {
                    return Err(PreviousBootFinalizationError::StaleSnapshot)
                }
                DurableOperationState::Failed { .. }
                | DurableOperationState::Indeterminate { .. } => {
                    return Err(PreviousBootFinalizationError::Conflicted)
                }
            };
            ledger.transition_with_operation(
                &authority.record_id,
                state,
                "record_resolution",
                DurableOperationState::Confirmed { attempt_id },
            )?;
        }
        _ => ledger.transition(&authority.record_id, state)?,
    }
    let next = current_record(ledger, &authority.record_id)?;
    Ok(PreviousBootFinalizationAuthority {
        sequence: next.sequence,
        file: ledger.record_file_identity(&authority.record_id)?,
        ..authority.clone_for_transition()
    })
}

pub(super) fn advance_runtime_release(
    ledger: &mut PersistentRecoveryLedger,
    authority: &PreviousBootFinalizationAuthority,
    operation_state: DurableOperationState,
) -> Result<PreviousBootFinalizationAuthority, PreviousBootFinalizationError> {
    let current = current_record(ledger, &authority.record_id)?;
    let file = ledger.record_file_identity(&authority.record_id)?;
    if !authority.validates(&current, &authority.current_boot, &file)
        || current.state != "record_resolved"
    {
        return Err(PreviousBootFinalizationError::StaleSnapshot);
    }
    ledger.transition_with_operation(
        &authority.record_id,
        "record_resolved",
        "runtime_release",
        operation_state,
    )?;
    let next = current_record(ledger, &authority.record_id)?;
    Ok(PreviousBootFinalizationAuthority {
        sequence: next.sequence,
        file: ledger.record_file_identity(&authority.record_id)?,
        ..authority.clone_for_transition()
    })
}

pub(super) fn guard_current_boot(
    ledger: &PersistentRecoveryLedger,
    host: &dyn PreviousBootInspectionHost,
    authority: &PreviousBootFinalizationAuthority,
) -> Result<(), PreviousBootFinalizationError> {
    let boot = host
        .current_boot_identity()
        .map_err(|_| PreviousBootFinalizationError::StaleSnapshot)?;
    let record = current_record(ledger, &authority.record_id)?;
    let file = ledger.record_file_identity(&authority.record_id)?;
    if !authority.validates(&record, &boot, &file) {
        return Err(PreviousBootFinalizationError::StaleSnapshot);
    }
    let epoch = RecoveryRecordEpoch::classify(record, boot)
        .map_err(|_| PreviousBootFinalizationError::StaleSnapshot)?;
    let RecoveryRecordEpoch::PreviousBoot(previous) = epoch else {
        return Err(PreviousBootFinalizationError::Conflicted);
    };
    let facts = host
        .inspect_current_snapshot(&PreviousBootInspectionRequest {
            record: previous,
            records: ledger.records().cloned().collect(),
        })
        .map_err(|_| PreviousBootFinalizationError::StaleSnapshot)?;
    if !facts.authority.stable || !facts.inspection_failures.is_empty() {
        return Err(PreviousBootFinalizationError::PlanChanged);
    }
    Ok(())
}
