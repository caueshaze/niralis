use super::*;
use std::io;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FinalizationCompletionProof {
    boot_id: BootIdentity,
    record_id: String,
    lifecycle_id: String,
    sequence: u64,
    seat: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PersistedRecordResolved {
    pub(super) boot_id: BootIdentity,
    pub(super) record_id: String,
    pub(super) lifecycle_id: String,
    pub(super) sequence: u64,
    pub(super) seat: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RuntimeReleasePermit {
    pub(super) boot_id: BootIdentity,
    pub(super) record_id: String,
    pub(super) lifecycle_id: String,
    pub(super) sequence: u64,
    pub(super) seat: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RuntimeReleaseConfirmed {
    pub(super) boot_id: BootIdentity,
    pub(super) record_id: String,
    pub(super) lifecycle_id: String,
    pub(super) sequence: u64,
    pub(super) seat: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RecordRemovalPermit {
    pub(super) boot_id: BootIdentity,
    pub(super) record_id: String,
    pub(super) lifecycle_id: String,
    pub(super) sequence: u64,
    pub(super) seat: String,
    pub(super) file_identity: RecordFileIdentity,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RecordFileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) links: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RecordRemovedReceipt {
    pub(super) boot_id: BootIdentity,
    pub(super) record_id: String,
    pub(super) lifecycle_id: String,
    pub(super) sequence: u64,
    pub(super) seat: String,
}

impl RecordRemovedReceipt {
    pub(crate) fn record_id(&self) -> &str {
        &self.record_id
    }
    pub(crate) fn lifecycle_id(&self) -> &str {
        &self.lifecycle_id
    }
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) fn seat(&self) -> &str {
        &self.seat
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SeatFreePermit {
    pub(super) boot_id: BootIdentity,
    pub(super) record_id: String,
    pub(super) lifecycle_id: String,
    pub(super) sequence: u64,
    pub(super) seat: String,
}

impl FinalizationCompletionProof {
    pub(crate) fn from_snapshot(
        snapshot: &RecoveryStateSnapshot,
    ) -> Result<Self, SupervisorRecoveryError> {
        if !snapshot.validates() {
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        Ok(Self {
            boot_id: snapshot.authority.boot_id().clone(),
            record_id: snapshot.record.lifecycle_id.clone(),
            lifecycle_id: snapshot.record.lifecycle_id.clone(),
            sequence: snapshot.record.sequence,
            seat: snapshot.record.seat.clone(),
        })
    }
}

pub(super) fn binding(
    boot_id: &BootIdentity,
    record: &PersistentRecoveryRecord,
) -> (BootIdentity, String, String, u64, String) {
    (
        boot_id.clone(),
        record.lifecycle_id.clone(),
        record.lifecycle_id.clone(),
        record.sequence,
        record.seat.clone(),
    )
}

impl PersistentRecoveryLedger {
    pub(crate) fn mark_record_resolved_typed(
        &mut self,
        snapshot: RecoveryStateSnapshot,
        completion: FinalizationCompletionProof,
    ) -> io::Result<(
        RecoveryStateSnapshot,
        PersistedRecordResolved,
        RuntimeReleasePermit,
    )> {
        if !snapshot.validates()
            || completion.boot_id != *snapshot.authority.boot_id()
            || completion.record_id != snapshot.record.lifecycle_id
            || completion.lifecycle_id != snapshot.record.lifecycle_id
            || completion.sequence != snapshot.record.sequence
            || completion.seat != snapshot.record.seat
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stale finalization proof",
            ));
        }
        let current = self
            .records
            .get(&snapshot.record.lifecycle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        if current.sequence != snapshot.record.sequence
            || current.lifecycle_id != snapshot.record.lifecycle_id
            || current.created_boot_id != snapshot.record.created_boot_id
            || current.seat != snapshot.record.seat
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stale recovery snapshot",
            ));
        }
        match current.operation_ledger.record_resolution {
            DurableOperationState::NotStarted => {
                let attempt = snapshot.record.sequence.saturating_add(1);
                self.operation_intent(&snapshot.record.lifecycle_id, "record_resolution", attempt)?;
                self.operation_confirmed(
                    &snapshot.record.lifecycle_id,
                    "record_resolution",
                    attempt,
                )?;
            }
            DurableOperationState::Confirmed { .. } => {}
            DurableOperationState::IntentPersisted { .. }
            | DurableOperationState::Indeterminate { .. }
            | DurableOperationState::Failed { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "record resolution is not replayable",
                ));
            }
        }
        self.mark_record_resolved(&snapshot.record.lifecycle_id)?;
        let record = self
            .records
            .get(&snapshot.record.lifecycle_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        let next = RecoveryStateSnapshot::from_record(snapshot.current_boot(), record.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid boot identity"))?;
        let (boot_id, record_id, lifecycle_id, sequence, seat) =
            binding(next.current_boot(), &record);
        let resolved = PersistedRecordResolved {
            boot_id: boot_id.clone(),
            record_id: record_id.clone(),
            lifecycle_id: lifecycle_id.clone(),
            sequence,
            seat: seat.clone(),
        };
        let permit = RuntimeReleasePermit {
            boot_id,
            record_id,
            lifecycle_id,
            sequence,
            seat,
        };
        Ok((next, resolved, permit))
    }
}
