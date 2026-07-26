use super::*;
use std::collections::BTreeSet;
use std::fs;
use std::io;

impl HistoricalFinalizationJournal {
    pub(crate) fn validate_against_ledger(
        &self,
        ledger: &PersistentRecoveryLedger,
    ) -> Result<(), HistoricalDurableStateConflict> {
        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            if !ids.insert(entry.record_id.clone()) {
                return Err(HistoricalDurableStateConflict::DuplicateRecordEntry);
            }
            let record = ledger
                .records()
                .find(|record| record.lifecycle_id == entry.record_id);
            let Some(record) = record else {
                if matches!(
                    entry.stage,
                    HistoricalFinalizationStage::RemovalIntent
                        | HistoricalFinalizationStage::Removed
                        | HistoricalFinalizationStage::FreePublished
                ) {
                    continue;
                }
                return Err(HistoricalDurableStateConflict::RecordMissingBeforeRemoval);
            };
            if record.seat != entry.seat || record.lifecycle_id != entry.lifecycle_id {
                return Err(HistoricalDurableStateConflict::SequenceConflict);
            }
            if entry.sequence > record.sequence {
                return Err(HistoricalDurableStateConflict::JournalAheadOfLedger);
            }
            if matches!(
                entry.stage,
                HistoricalFinalizationStage::Removed | HistoricalFinalizationStage::FreePublished
            ) {
                return Err(HistoricalDurableStateConflict::RecordPresentAfterRemovalReceipt);
            }
            if matches!(
                entry.stage,
                HistoricalFinalizationStage::RecordResolved
                    | HistoricalFinalizationStage::RuntimeReleaseIntent
                    | HistoricalFinalizationStage::RuntimeReleaseConfirmed
                    | HistoricalFinalizationStage::RemovalIntent
            ) && record.state != "record_resolved"
            {
                return Err(HistoricalDurableStateConflict::LedgerAheadOfJournal);
            }
            if matches!(
                entry.stage,
                HistoricalFinalizationStage::RuntimeReleaseIntent
            ) && !matches!(
                record.operation_ledger.runtime_release,
                DurableOperationState::IntentPersisted { .. }
                    | DurableOperationState::Confirmed { .. }
            ) {
                return Err(HistoricalDurableStateConflict::JournalAheadOfLedger);
            }
            if entry.stage == HistoricalFinalizationStage::RecordResolved
                && !matches!(
                    record.operation_ledger.runtime_release,
                    DurableOperationState::NotStarted
                )
            {
                return Err(HistoricalDurableStateConflict::LedgerAheadOfJournal);
            }
            if matches!(
                entry.stage,
                HistoricalFinalizationStage::RuntimeReleaseConfirmed
                    | HistoricalFinalizationStage::RemovalIntent
            ) && !matches!(
                record.operation_ledger.runtime_release,
                DurableOperationState::Confirmed { .. }
            ) {
                return Err(HistoricalDurableStateConflict::JournalAheadOfLedger);
            }
            if let (Some(device), Some(inode)) = (entry.device, entry.inode) {
                let current = ledger
                    .record_file_identity(&entry.record_id)
                    .map_err(|_| HistoricalDurableStateConflict::ReplacedInode)?;
                if current.device != device || current.inode != inode || current.links != 1 {
                    return Err(HistoricalDurableStateConflict::ReplacedInode);
                }
            }
        }
        Ok(())
    }
}

pub(super) fn validate_journal_files(ledger: &PersistentRecoveryLedger) -> io::Result<()> {
    let tmp = ledger.directory.join(".previous-boot-finalization.tmp");
    if tmp.exists() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{:?}",
                HistoricalDurableStateConflict::AbandonedTemporaryFile
            ),
        ));
    }
    let candidates = fs::read_dir(&ledger.directory)
        .map_err(io::Error::other)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("previous-boot-finalization")
                && entry.path() != ledger.historical_journal_path()
        })
        .count();
    if candidates != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{:?}",
                HistoricalDurableStateConflict::DuplicateJournalCandidate
            ),
        ));
    }
    Ok(())
}
