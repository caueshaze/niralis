use super::*;

pub(crate) fn execute_previous_boot_plan(
    ledger: &mut PersistentRecoveryLedger,
    host: &dyn PreviousBootInspectionHost,
    record: &PreviousBootRecoveryRecord,
    facts: &PreviousBootCurrentFacts,
    plan: &PreviousBootRecoveryPlan,
) -> Result<PreviousBootFinalizationOutcome, PreviousBootFinalizationError> {
    if !matches!(
        plan,
        PreviousBootRecoveryPlan::ResolveHistoricalRecord
            | PreviousBootRecoveryPlan::FinalizeAlreadyResolvedRecord
    ) {
        return Ok(PreviousBootFinalizationOutcome::PreservedQuarantine);
    }
    hit_previous_boot_failpoint(PreviousBootFailpoint::BeforeResolutionIntent);
    let file = ledger.record_file_identity(&record.record.lifecycle_id)?;
    let authority = revalidate(ledger, host, record, facts, plan, &file)?;
    let mut journal = HistoricalFinalizationJournal::load(ledger)?;
    if let Err(conflict) = journal.validate_against_ledger(ledger) {
        warn!(record_id = %record.record.lifecycle_id, conflict = ?conflict, "durable_state_conflict");
        return Err(conflict.into());
    }
    info!(
        record_id = %authority.record_id,
        sequence = authority.sequence,
        current_boot = %authority.current_boot.as_str(),
        recorded_boot = %authority.recorded_boot.as_str(),
        "previous_boot_plan_revalidated"
    );
    let current = current_record(ledger, &authority.record_id)?;
    let existing_stage = journal.entry(&authority.record_id).map(|entry| entry.stage);
    let mut entry = HistoricalFinalizationEntry {
        record_id: authority.record_id.clone(),
        lifecycle_id: authority.lifecycle_id.clone(),
        seat: authority.seat.clone(),
        boot_id: authority.current_boot.as_str().to_owned(),
        sequence: authority.sequence,
        stage: HistoricalFinalizationStage::NotReplayed,
        not_replayed: historical_not_replayed(&current),
        device: Some(file.device),
        inode: Some(file.inode),
        links: Some(file.links),
    };
    if matches!(plan, PreviousBootRecoveryPlan::ResolveHistoricalRecord)
        && !matches!(
            existing_stage,
            Some(
                HistoricalFinalizationStage::RecordResolved
                    | HistoricalFinalizationStage::RuntimeReleaseIntent
                    | HistoricalFinalizationStage::RuntimeReleaseConfirmed
                    | HistoricalFinalizationStage::RemovalIntent
                    | HistoricalFinalizationStage::Removed
                    | HistoricalFinalizationStage::FreePublished
            )
        )
    {
        if existing_stage.is_none() {
            journal.upsert(entry.clone());
            journal.persist(ledger)?;
            for historical in &entry.not_replayed {
                info!(
                    record_id = %entry.record_id,
                    operation = %historical.operation,
                    attempt_id = ?historical.attempt_id,
                    "historical_operation_not_replayed"
                );
            }
            hit_previous_boot_failpoint(PreviousBootFailpoint::AfterNotReplayed);
            entry.stage = HistoricalFinalizationStage::ResolutionIntent;
            journal.upsert(entry.clone());
            journal.persist(ledger)?;
        }
        let _permit = HistoricalResolutionPermit(authority.clone_for_transition());
        let mut current_authority = authority;
        if current.state != "previous_boot_resolution_intent" {
            guard_current_boot(ledger, host, &current_authority)?;
            current_authority = advance(
                ledger,
                &current_authority,
                "previous_boot_resolution_intent",
            )?;
        }
        entry.sequence = current_authority.sequence;
        entry.device = Some(current_authority.file.device);
        entry.inode = Some(current_authority.file.inode);
        entry.links = Some(current_authority.file.links);
        journal.upsert(entry.clone());
        journal.persist(ledger)?;
        hit_previous_boot_failpoint(PreviousBootFailpoint::AfterResolutionIntent);
        if current_record(ledger, &current_authority.record_id)?.state != "record_resolved" {
            guard_current_boot(ledger, host, &current_authority)?;
            current_authority = advance(ledger, &current_authority, "record_resolved")?;
        }
        let _persisted = PersistedHistoricalResolution(current_authority.clone_for_transition());
        entry.sequence = current_authority.sequence;
        entry.device = Some(current_authority.file.device);
        entry.inode = Some(current_authority.file.inode);
        entry.links = Some(current_authority.file.links);
        entry.stage = HistoricalFinalizationStage::RecordResolved;
        journal.upsert(entry.clone());
        journal.persist(ledger)?;
        hit_previous_boot_failpoint(PreviousBootFailpoint::AfterHistoricalResolved);
        authority_for_runtime(ledger, host, current_authority, &mut journal, entry)
    } else {
        info!(record_id = %authority.record_id, sequence = authority.sequence, "historical_finalization_resumed");
        let authority = if matches!(
            current_record(ledger, &authority.record_id)?
                .operation_ledger
                .record_resolution,
            DurableOperationState::NotStarted
        ) {
            advance(ledger, &authority, "record_resolved")?
        } else {
            authority
        };
        authority_for_runtime(ledger, host, authority, &mut journal, entry)
    }
}

fn authority_for_runtime(
    ledger: &mut PersistentRecoveryLedger,
    host: &dyn PreviousBootInspectionHost,
    authority: PreviousBootFinalizationAuthority,
    journal: &mut HistoricalFinalizationJournal,
    mut entry: HistoricalFinalizationEntry,
) -> Result<PreviousBootFinalizationOutcome, PreviousBootFinalizationError> {
    let current = current_record(ledger, &authority.record_id)?;
    let (intent_authority, attempt_id) = match current.operation_ledger.runtime_release {
        DurableOperationState::NotStarted => {
            let next = advance_runtime_release(
                ledger,
                &authority,
                DurableOperationState::IntentPersisted {
                    attempt_id: authority.sequence.saturating_add(1),
                },
            )?;
            entry.sequence = next.sequence;
            entry.device = Some(next.file.device);
            entry.inode = Some(next.file.inode);
            entry.links = Some(next.file.links);
            entry.stage = HistoricalFinalizationStage::RuntimeReleaseIntent;
            journal.upsert(entry.clone());
            journal.persist(ledger)?;
            hit_previous_boot_failpoint(PreviousBootFailpoint::AfterRuntimeReleaseIntent);
            let attempt_id = match current_record(ledger, &next.record_id)?
                .operation_ledger
                .runtime_release
            {
                DurableOperationState::IntentPersisted { attempt_id } => attempt_id,
                _ => return Err(PreviousBootFinalizationError::StaleSnapshot),
            };
            (next, attempt_id)
        }
        DurableOperationState::IntentPersisted { attempt_id } => (authority, attempt_id),
        DurableOperationState::Confirmed { attempt_id } => (authority, attempt_id),
        DurableOperationState::Failed { .. } | DurableOperationState::Indeterminate { .. } => {
            return Err(PreviousBootFinalizationError::Conflicted)
        }
    };
    let permit = HistoricalRuntimeReleasePermit(intent_authority.clone_for_transition());
    guard_current_boot(ledger, host, &permit.0)?;
    let authority = if matches!(
        current_record(ledger, &permit.0.record_id)?
            .operation_ledger
            .runtime_release,
        DurableOperationState::Confirmed { .. }
    ) {
        permit.0.clone_for_transition()
    } else {
        advance_runtime_release(
            ledger,
            &permit.0,
            DurableOperationState::Confirmed { attempt_id },
        )?
    };
    let _confirmed = HistoricalRuntimeReleaseConfirmed(authority.clone_for_transition());
    entry.sequence = authority.sequence;
    entry.device = Some(authority.file.device);
    entry.inode = Some(authority.file.inode);
    entry.links = Some(authority.file.links);
    entry.stage = HistoricalFinalizationStage::RuntimeReleaseConfirmed;
    journal.upsert(entry.clone());
    journal.persist(ledger)?;
    hit_previous_boot_failpoint(PreviousBootFailpoint::AfterRuntimeReleaseConfirmed);
    let removal = HistoricalRecordRemovalPermit {
        authority: authority.clone_for_transition(),
        file: authority.file,
    };
    entry.sequence = authority.sequence;
    entry.stage = HistoricalFinalizationStage::RemovalIntent;
    journal.upsert(entry.clone());
    journal.persist(ledger)?;
    hit_previous_boot_failpoint(PreviousBootFailpoint::BeforeUnlink);
    guard_current_boot(ledger, host, &removal.authority)?;
    ledger.remove_record_exact(&removal.authority.record_id, &removal.file)?;
    hit_previous_boot_failpoint(PreviousBootFailpoint::AfterUnlinkBeforeReceipt);
    let receipt = HistoricalRecordRemovedReceipt(removal.authority.clone_for_transition());
    entry.sequence = receipt.0.sequence;
    entry.stage = HistoricalFinalizationStage::Removed;
    journal.upsert(entry.clone());
    journal.persist(ledger)?;
    hit_previous_boot_failpoint(PreviousBootFailpoint::AfterRemovalReceipt);
    let free = HistoricalSeatFreePermit(receipt.0.clone_for_transition());
    hit_previous_boot_failpoint(PreviousBootFailpoint::BeforeSeatFree);
    ledger.clear_seat_startup_quarantine(&free.0.seat);
    entry.stage = HistoricalFinalizationStage::FreePublished;
    journal.upsert(entry);
    journal.persist(ledger)?;
    info!(record_id = %receipt.0.record_id, sequence = receipt.0.sequence, "seat_free_after_historical_completion");
    Ok(PreviousBootFinalizationOutcome::SeatFreed)
}
