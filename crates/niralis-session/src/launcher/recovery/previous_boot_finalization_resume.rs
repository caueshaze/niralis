use super::*;

pub(crate) fn resume_removed_previous_boot_finalization(
    ledger: &mut PersistentRecoveryLedger,
) -> Result<usize, PreviousBootFinalizationError> {
    let mut journal = HistoricalFinalizationJournal::load(ledger)?;
    if let Err(conflict) = journal.validate_against_ledger(ledger) {
        warn!(conflict = ?conflict, "durable_state_conflict");
        return Err(conflict.into());
    }
    let mut completed = 0;
    if ledger.startup_quarantined() {
        return Ok(0);
    }
    for entry in journal.entries.clone() {
        if !matches!(
            entry.stage,
            HistoricalFinalizationStage::Removed | HistoricalFinalizationStage::RemovalIntent
        ) || ledger
            .records()
            .any(|record| record.lifecycle_id == entry.record_id)
        {
            continue;
        }
        if matches!(entry.stage, HistoricalFinalizationStage::RemovalIntent)
            && ledger.record_file_exists(&entry.record_id)?
        {
            continue;
        }
        ledger.clear_seat_startup_quarantine(&entry.seat);
        info!(record_id = %entry.record_id, sequence = entry.sequence, "record_already_removed_with_valid_receipt");
        let mut next = entry;
        next.stage = HistoricalFinalizationStage::FreePublished;
        journal.upsert(next);
        completed += 1;
    }
    if completed != 0 {
        journal.persist(ledger)?;
    }
    Ok(completed)
}
