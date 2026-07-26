use super::*;
use std::io;

impl PersistentRecoveryLedger {
    pub(crate) fn persist_recovery_unref_intent(
        &mut self,
        snapshot: RecoveryStateSnapshot,
        proof: RecoveryBoundaryEmptyProof,
        attempt_id: u64,
    ) -> io::Result<(
        RecoveryStateSnapshot,
        RecoveryOperationPermit<SupervisorUnrefOperation>,
        AuthorizedRecoveryBoundaryProof,
    )> {
        if !snapshot.validates() || !proof.matches_snapshot(&snapshot) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "foreign recovery boundary proof",
            ));
        }
        let (next_snapshot, permit) = self
            .persist_recovery_intent_from_snapshot::<SupervisorUnrefOperation>(
                snapshot,
                "supervisor_unref",
                attempt_id,
            )?;
        let authorized_proof = proof.authorize(next_snapshot.record.sequence);
        Ok((next_snapshot, permit, authorized_proof))
    }

    pub(crate) fn persist_recovery_intent_from_snapshot<K>(
        &mut self,
        snapshot: RecoveryStateSnapshot,
        operation: &str,
        attempt_id: u64,
    ) -> io::Result<(RecoveryStateSnapshot, RecoveryOperationPermit<K>)> {
        if !snapshot.validates() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stale recovery snapshot",
            ));
        }
        let id = snapshot.record.lifecycle_id.clone();
        self.operation_intent(&id, operation, attempt_id)?;
        let record = self
            .records
            .get(&id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        let next_snapshot =
            RecoveryStateSnapshot::from_record(snapshot.current_boot(), record.clone()).map_err(
                |_| io::Error::new(io::ErrorKind::InvalidData, "invalid recovery boot identity"),
            )?;
        let permit = make_recovery_permit(&record, attempt_id).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid recovery boot identity")
        })?;
        Ok((next_snapshot, permit))
    }

    pub(crate) fn refresh_recovery_snapshot(
        &self,
        snapshot: RecoveryStateSnapshot,
    ) -> io::Result<RecoveryStateSnapshot> {
        if !snapshot.validates() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stale recovery snapshot",
            ));
        }
        let record = self
            .records
            .get(&snapshot.record.lifecycle_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        RecoveryStateSnapshot::from_record(snapshot.current_boot(), record).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid recovery boot identity")
        })
    }
}
