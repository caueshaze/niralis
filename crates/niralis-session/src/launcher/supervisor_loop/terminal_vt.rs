use super::*;

impl SupervisorLoopState {
    pub(super) fn resolve_clean_worker_record(
        &mut self,
        worker_id: &str,
    ) -> Result<(), SessionError> {
        let Some(ledger) = &self.ledger else {
            return Ok(());
        };
        ledger
            .lock()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .resolve_and_remove(worker_id)
            .map_err(|_| SessionError::WorkerIoFailed)
    }

    pub(super) fn accept_terminal_vt_intent(
        &mut self,
        worker_id: &str,
        worker_pid: u32,
        registration_nonce: &str,
        identity: &crate::PayloadScopeIdentity,
    ) -> Result<u64, SessionError> {
        let worker = self
            .children
            .iter_mut()
            .find(|worker| worker.worker_id == worker_id)
            .ok_or(SessionError::WorkerProtocolFailed)?;
        if worker.record.worker_pid != worker_pid
            || worker.registration_nonce != registration_nonce
            || worker.record.payload_identity() != Some(identity)
            || registration_nonce.is_empty()
            || registration_nonce.len() > 128
        {
            return Err(SessionError::WorkerProtocolFailed);
        }
        let Some(ledger) = &self.ledger else {
            return Err(SessionError::WorkerIoFailed);
        };
        let mut ledger = ledger.lock().map_err(|_| SessionError::WorkerIoFailed)?;
        let record = ledger
            .records
            .get(worker_id)
            .ok_or(SessionError::WorkerProtocolFailed)?;
        if record.worker_pid != worker_pid || record.state != "started" {
            return Err(SessionError::WorkerProtocolFailed);
        }
        let attempt_id = record
            .sequence
            .checked_add(1)
            .ok_or(SessionError::WorkerProtocolFailed)?;
        ledger
            .worker_vt_cleanup_intent(worker_id, attempt_id)
            .map_err(|_| SessionError::WorkerIoFailed)?;
        Ok(attempt_id)
    }

    pub(super) fn accept_terminal_vt_result(
        &mut self,
        worker_id: &str,
        worker_pid: u32,
        registration_nonce: &str,
        attempt_id: u64,
        result: crate::TerminalVtCleanupResult,
    ) -> Result<(), SessionError> {
        if registration_nonce.is_empty() || registration_nonce.len() > 128 {
            return Err(SessionError::WorkerProtocolFailed);
        }
        let worker = self
            .children
            .iter_mut()
            .find(|worker| worker.worker_id == worker_id)
            .ok_or(SessionError::WorkerProtocolFailed)?;
        if worker.record.worker_pid != worker_pid || worker.registration_nonce != registration_nonce
        {
            return Err(SessionError::WorkerProtocolFailed);
        }
        let Some(ledger) = &self.ledger else {
            return Err(SessionError::WorkerIoFailed);
        };
        let mut ledger = ledger.lock().map_err(|_| SessionError::WorkerIoFailed)?;
        let record = ledger
            .records
            .get(worker_id)
            .ok_or(SessionError::WorkerProtocolFailed)?;
        if !matches!(record.operation_ledger.vt_disallocate, DurableOperationState::IntentPersisted { attempt_id: id } if id == attempt_id)
        {
            return Err(SessionError::WorkerProtocolFailed);
        }
        ledger
            .worker_vt_cleanup_result(worker_id, attempt_id, result)
            .map_err(|_| SessionError::WorkerIoFailed)?;
        worker.terminal_vt_reported_busy =
            matches!(result, crate::TerminalVtCleanupResult::VtDisallocateBusy);
        Ok(())
    }
}
