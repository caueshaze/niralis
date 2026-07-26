use super::*;
use std::io;

fn finalization_capabilities(
    ledger: &PersistentRecoveryLedger,
    snapshot: &RecoveryStateSnapshot,
) -> io::Result<(
    PersistedRecordResolved,
    RuntimeReleaseConfirmed,
    RecordRemovalPermit,
)> {
    let (boot_id, record_id, lifecycle_id, sequence, seat) =
        binding(snapshot.current_boot(), &snapshot.record);
    let resolved = PersistedRecordResolved {
        boot_id: boot_id.clone(),
        record_id: record_id.clone(),
        lifecycle_id: lifecycle_id.clone(),
        sequence,
        seat: seat.clone(),
    };
    let confirmed = RuntimeReleaseConfirmed {
        boot_id: boot_id.clone(),
        record_id: record_id.clone(),
        lifecycle_id: lifecycle_id.clone(),
        sequence,
        seat: seat.clone(),
    };
    let removal = RecordRemovalPermit {
        boot_id,
        record_id,
        lifecycle_id,
        sequence,
        seat,
        file_identity: ledger.record_file_identity(&snapshot.record.lifecycle_id)?,
    };
    Ok((resolved, confirmed, removal))
}

impl PersistentRecoveryLedger {
    pub(crate) fn finalize_startup_record(
        &mut self,
        record_id: &str,
    ) -> io::Result<SeatFreePermit> {
        let record = self
            .records
            .get(record_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        if matches!(
            record.operation_ledger.runtime_release,
            DurableOperationState::IntentPersisted { .. }
                | DurableOperationState::Indeterminate { .. }
                | DurableOperationState::Failed { .. }
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime release is not replayable",
            ));
        }
        let boot = BootIdentity::parse(record.created_boot_id.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid boot identity"))?;
        let snapshot = RecoveryStateSnapshot::from_record(&boot, record)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "stale recovery record"))?;
        let (snapshot, resolved) = if snapshot.record.state == "record_resolved" {
            let (resolved, _, _) = finalization_capabilities(self, &snapshot)?;
            (snapshot, resolved)
        } else {
            let completion = FinalizationCompletionProof::from_snapshot(&snapshot)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid completion"))?;
            let (snapshot, resolved, _) = self.mark_record_resolved_typed(snapshot, completion)?;
            (snapshot, resolved)
        };
        if !matches!(
            snapshot.record.operation_ledger.runtime_release,
            DurableOperationState::Confirmed { .. }
        ) {
            let (next, permit) = self
                .persist_recovery_intent_from_snapshot::<RuntimeReleaseOperation>(
                    snapshot,
                    "runtime_release",
                    resolved.sequence.saturating_add(1),
                )?;
            self.operation_confirmed(record_id, "runtime_release", permit.attempt_id())?;
            let snapshot = self.refresh_recovery_snapshot(next)?;
            let (resolved, confirmed, removal) = finalization_capabilities(self, &snapshot)?;
            let receipt = self.remove_record_typed(snapshot, resolved, confirmed, removal)?;
            return self.issue_seat_free_permit(receipt);
        }
        let (resolved, confirmed, removal) = finalization_capabilities(self, &snapshot)?;
        let receipt = self.remove_record_typed(snapshot, resolved, confirmed, removal)?;
        self.issue_seat_free_permit(receipt)
    }
}
