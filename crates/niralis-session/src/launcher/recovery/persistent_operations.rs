use super::*;
use std::io;

impl PersistentRecoveryLedger {
    pub(crate) fn record_vt_busy_provenance(
        &mut self,
        id: &str,
        provenance: crate::VtBusyProvenance,
    ) -> io::Result<()> {
        let mut next = self.record_for_operation(id)?;
        next.vt_busy_provenance = Some(provenance);
        let state = next.state.clone();
        self.commit_transition(next, &state)
    }

    pub(crate) fn append_vt_recovery_attempt(
        &mut self,
        id: &str,
        attempt: crate::VtRecoveryAttempt,
    ) -> io::Result<()> {
        let mut next = self.record_for_operation(id)?;
        next.vt_recovery_attempts.push(attempt);
        if next.vt_recovery_attempts.len() > crate::MAX_VT_RECOVERY_ATTEMPTS {
            next.vt_recovery_attempts.remove(0);
        }
        let state = next.state.clone();
        self.commit_transition(next, &state)
    }

    pub(crate) fn finish_vt_recovery_attempt(
        &mut self,
        id: &str,
        attempt_id: u64,
        state: crate::VtRecoveryAttemptState,
        provenance_after: Option<crate::VtBusyProvenance>,
    ) -> io::Result<()> {
        let mut next = self.record_for_operation(id)?;
        let attempt = next
            .vt_recovery_attempts
            .iter_mut()
            .rev()
            .find(|attempt| attempt.attempt_id == attempt_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "VT recovery attempt"))?;
        if !matches!(
            attempt.state,
            crate::VtRecoveryAttemptState::IntentPersisted
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VT recovery attempt is not pending",
            ));
        }
        attempt.state = state;
        attempt.provenance_after = provenance_after;
        let current = next.state.clone();
        self.commit_transition(next, &current)
    }
    pub(crate) fn worker_vt_cleanup_intent(&mut self, id: &str, attempt_id: u64) -> io::Result<()> {
        let mut next = self.record_for_operation(id)?;
        next.pam_status = "closed_by_worker_confirmed".to_owned();
        next.operation_ledger.vt_disallocate =
            DurableOperationState::IntentPersisted { attempt_id };
        self.commit_transition(next, "started")?;
        info!(
            lifecycle_id = id,
            attempt_id, "worker terminal VT cleanup intent persisted"
        );
        Ok(())
    }

    pub(crate) fn worker_vt_cleanup_result(
        &mut self,
        id: &str,
        attempt_id: u64,
        result: crate::TerminalVtCleanupResult,
    ) -> io::Result<()> {
        let mut next = self.record_for_operation(id)?;
        let state = match result {
            crate::TerminalVtCleanupResult::Released => {
                next.operation_ledger.vt_disallocate =
                    DurableOperationState::Confirmed { attempt_id };
                "started"
            }
            crate::TerminalVtCleanupResult::VtDisallocateBusy => {
                next.operation_ledger.vt_disallocate = DurableOperationState::Failed {
                    attempt_id,
                    failure_class: libc::EBUSY,
                };
                "vt_disallocate_failed_busy"
            }
        };
        self.commit_transition(next, state)?;
        info!(
            lifecycle_id = id,
            attempt_id,
            result = ?result,
            "worker terminal VT cleanup result persisted"
        );
        Ok(())
    }

    fn record_for_operation(&self, id: &str) -> io::Result<PersistentRecoveryRecord> {
        self.records
            .get(id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))
    }

    fn commit_transition(
        &mut self,
        mut next: PersistentRecoveryRecord,
        state: &str,
    ) -> io::Result<()> {
        next.transition(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.commit(next)
    }
    pub(crate) fn operation_intent(
        &mut self,
        id: &str,
        operation: &str,
        attempt_id: u64,
    ) -> io::Result<()> {
        self.update_operation(
            id,
            operation,
            DurableOperationState::IntentPersisted { attempt_id },
        )
    }

    pub(crate) fn operation_confirmed(
        &mut self,
        id: &str,
        operation: &str,
        attempt_id: u64,
    ) -> io::Result<()> {
        self.update_operation(
            id,
            operation,
            DurableOperationState::Confirmed { attempt_id },
        )
    }

    pub(crate) fn operation_failed(
        &mut self,
        id: &str,
        operation: &str,
        attempt_id: u64,
        failure_class: i32,
    ) -> io::Result<()> {
        self.update_operation(
            id,
            operation,
            DurableOperationState::Failed {
                attempt_id,
                failure_class,
            },
        )
    }

    fn update_operation(
        &mut self,
        id: &str,
        operation: &str,
        state: DurableOperationState,
    ) -> io::Result<()> {
        let mut next = self
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        match operation {
            "payload_kill" => next.operation_ledger.payload_kill = state,
            "supervisor_unref" => next.operation_ledger.supervisor_unref = state,
            "logind_termination" => next.operation_ledger.logind_termination = state,
            "selinux_restore" => next.operation_ledger.selinux_restore = state,
            "vt_activation" => next.operation_ledger.vt_activation = state,
            "vt_disallocate" => next.operation_ledger.vt_disallocate = state,
            "runtime_release" => next.operation_ledger.runtime_release = state,
            "record_resolution" => next.operation_ledger.record_resolution = state,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown operation",
                ))
            }
        }
        let current = next.state.clone();
        next.transition(&current)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.commit(next)
    }
}
