use super::*;
use std::io;

fn matches_binding(
    snapshot: &RecoveryStateSnapshot,
    boot_id: &BootIdentity,
    record_id: &str,
    lifecycle_id: &str,
    sequence: u64,
    seat: &str,
) -> bool {
    boot_id == snapshot.authority.boot_id()
        && record_id == snapshot.record.lifecycle_id
        && lifecycle_id == snapshot.record.lifecycle_id
        && sequence == snapshot.record.sequence
        && seat == snapshot.record.seat
}

impl PersistentRecoveryLedger {
    pub(crate) fn confirm_runtime_release_typed(
        &mut self,
        snapshot: RecoveryStateSnapshot,
        resolved: PersistedRecordResolved,
        permit: RuntimeReleasePermit,
    ) -> io::Result<(
        RecoveryStateSnapshot,
        PersistedRecordResolved,
        RuntimeReleaseConfirmed,
        RecordRemovalPermit,
    )> {
        let record = self
            .records
            .get(&snapshot.record.lifecycle_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        if !snapshot.validates()
            || record.state != "record_resolved"
            || !matches_binding(
                &snapshot,
                &resolved.boot_id,
                &resolved.record_id,
                &resolved.lifecycle_id,
                resolved.sequence,
                &resolved.seat,
            )
            || !matches_binding(
                &snapshot,
                &permit.boot_id,
                &permit.record_id,
                &permit.lifecycle_id,
                permit.sequence,
                &permit.seat,
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime release capability mismatch",
            ));
        }
        self.operation_confirmed(&record.lifecycle_id, "runtime_release", record.sequence)?;
        let next = self.refresh_recovery_snapshot(snapshot)?;
        let (boot_id, record_id, lifecycle_id, sequence, seat) =
            binding(next.current_boot(), &next.record);
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
            file_identity: self.record_file_identity(&record.lifecycle_id)?,
        };
        let resolved = PersistedRecordResolved {
            boot_id: confirmed.boot_id.clone(),
            record_id: confirmed.record_id.clone(),
            lifecycle_id: confirmed.lifecycle_id.clone(),
            sequence: confirmed.sequence,
            seat: confirmed.seat.clone(),
        };
        Ok((next, resolved, confirmed, removal))
    }

    pub(crate) fn remove_record_typed(
        &mut self,
        snapshot: RecoveryStateSnapshot,
        resolved: PersistedRecordResolved,
        confirmed: RuntimeReleaseConfirmed,
        permit: RecordRemovalPermit,
    ) -> io::Result<RecordRemovedReceipt> {
        let record = self
            .records
            .get(&snapshot.record.lifecycle_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        if !snapshot.validates()
            || !matches_binding(
                &snapshot,
                &resolved.boot_id,
                &resolved.record_id,
                &resolved.lifecycle_id,
                resolved.sequence,
                &resolved.seat,
            )
            || !matches_binding(
                &snapshot,
                &confirmed.boot_id,
                &confirmed.record_id,
                &confirmed.lifecycle_id,
                confirmed.sequence,
                &confirmed.seat,
            )
            || !matches_binding(
                &snapshot,
                &permit.boot_id,
                &permit.record_id,
                &permit.lifecycle_id,
                permit.sequence,
                &permit.seat,
            )
            || record.state != "record_resolved"
            || !matches!(
                record.operation_ledger.runtime_release,
                DurableOperationState::Confirmed { .. }
            )
            || self.record_file_identity(&record.lifecycle_id)? != permit.file_identity
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "record removal capability mismatch",
            ));
        }
        let sequence = record.sequence;
        self.remove_resolved(&record.lifecycle_id)?;
        Ok(RecordRemovedReceipt {
            boot_id: permit.boot_id,
            record_id: permit.record_id,
            lifecycle_id: permit.lifecycle_id,
            sequence,
            seat: permit.seat,
        })
    }
}
