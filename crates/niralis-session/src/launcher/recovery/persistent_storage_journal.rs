use super::*;

pub(super) fn apply_historical_journal_quarantine(ledger: &mut PersistentRecoveryLedger) {
    if !ledger.historical_journal_path().exists() {
        return;
    }
    match HistoricalFinalizationJournal::load(ledger) {
        Ok(journal) => {
            for entry in journal.entries {
                if entry.stage != HistoricalFinalizationStage::FreePublished {
                    ledger.startup_quarantined_seats.insert(entry.seat);
                }
            }
        }
        Err(error) => {
            warn!(error = %error, "durable_state_conflict");
            ledger.startup_quarantined = true;
        }
    }
}
