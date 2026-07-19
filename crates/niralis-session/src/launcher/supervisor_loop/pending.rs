use super::*;
use tracing::warn;

impl SupervisorLoopState {
    pub(super) fn reserve_seat(
        &mut self,
        worker_id: String,
    ) -> Result<PreviousVtIdentity, SessionError> {
        if worker_id.is_empty() || !matches!(self.seat, SeatLifecycle::Free) {
            return Err(SessionError::SessionSeatUnavailable);
        }
        let previous_vt = self
            .recovery_provider
            .capture_previous_vt("seat0")
            .map_err(|_| SessionError::WorkerIoFailed)?;
        self.seat = SeatLifecycle::Active {
            lifecycle_id: worker_id,
        };
        Ok(previous_vt)
    }

    pub(super) fn cancel_seat_reservation(&mut self, worker_id: &str) {
        if matches!(&self.seat, SeatLifecycle::Active { lifecycle_id } if lifecycle_id == worker_id)
            && !self
                .pending
                .iter()
                .any(|entry| entry.record.lifecycle_id == worker_id)
        {
            self.seat = SeatLifecycle::Free;
        }
    }

    pub(super) fn begin_pending(
        &mut self,
        worker_id: String,
        worker_pid: u32,
        launcher_pid: u32,
        session: StartedSession,
        child: Arc<Mutex<Child>>,
        previous_vt: PreviousVtIdentity,
    ) -> Result<(), SessionError> {
        if worker_id.is_empty()
            || worker_pid == 0
            || launcher_pid != std::process::id()
            || !matches!(&self.seat, SeatLifecycle::Active { lifecycle_id } if lifecycle_id == &worker_id)
            || self
                .pending
                .iter()
                .any(|entry| entry.record.lifecycle_id == worker_id)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.pending.push(PendingWorkerLifecycle {
            record: SupervisorSessionRecoveryRecord::worker_spawned(
                worker_id,
                worker_pid,
                launcher_pid,
                &session,
                previous_vt,
            ),
            child,
            release: PendingReleaseState::NotRequested,
            generation: 0,
            terminal_before_started: false,
        });
        Ok(())
    }

    pub(super) fn record_prepared_scope(
        &mut self,
        worker_id: String,
        worker_pid: u32,
        session_pid: u32,
        identity: crate::PayloadScopeIdentity,
        registration_nonce: String,
    ) -> Result<(), SessionError> {
        let ledger = self.ledger.clone();
        let entry = self
            .pending
            .iter_mut()
            .find(|entry| {
                entry.record.lifecycle_id == worker_id && entry.record.worker_pid == worker_pid
            })
            .ok_or(SessionError::WorkerProtocolFailed)?;
        if entry.terminal_before_started
            || !matches!(entry.release, PendingReleaseState::NotRequested)
            || registration_nonce.is_empty()
            || registration_nonce.len() > 128
        {
            return Err(SessionError::WorkerProtocolFailed);
        }
        let state = entry.record.take_state_for_transition();
        let SupervisorRecoveryState::WorkerSpawned { previous_vt } = state else {
            entry.record.state = state;
            return Err(SessionError::WorkerProtocolFailed);
        };
        match self.recovery_provider.prepare_payload(
            &identity,
            session_pid,
            worker_pid,
            entry.record.launcher_pid,
            &previous_vt,
        ) {
            Ok(payload) => {
                let durable = PersistentRecoveryRecord::prepared(
                    &entry.record.lifecycle_id,
                    worker_pid,
                    entry.record.launcher_pid,
                    &entry.record.requested_username,
                    &entry.record.session_name,
                    &previous_vt,
                    &payload,
                );
                persist_new_record_to(&ledger, durable)?;
                entry.record.state = SupervisorRecoveryState::PayloadPrepared {
                    payload,
                    registration_nonce,
                };
                entry.generation = entry.generation.wrapping_add(1);
                Ok(())
            }
            Err(error) => {
                warn!(
                    ?error,
                    worker_id, "supervisor payload preparation failed before acknowledgement"
                );
                entry.record.state = SupervisorRecoveryState::Quarantined {
                    stage: EmergencyRecoveryStage::PayloadIdentityValidation,
                    reason: SupervisorRecoveryError::InvalidPayloadIdentity,
                    retained_identity: SupervisorRetainedRecoveryIdentity::PrePayload {
                        previous_vt,
                    },
                };
                entry.terminal_before_started = true;
                self.seat = SeatLifecycle::Quarantined {
                    lifecycle_id: worker_id,
                    stage: EmergencyRecoveryStage::PayloadIdentityValidation,
                    reason: SupervisorRecoveryError::InvalidPayloadIdentity,
                };
                Err(SessionError::WorkerProtocolFailed)
            }
        }
    }

    pub(super) fn mark_payload_registered(
        &mut self,
        worker_id: &str,
        worker_pid: u32,
    ) -> Result<(), SessionError> {
        let entry = self
            .pending
            .iter_mut()
            .find(|entry| {
                entry.record.lifecycle_id == worker_id && entry.record.worker_pid == worker_pid
            })
            .ok_or(SessionError::WorkerProtocolFailed)?;
        let state = entry.record.take_state_for_transition();
        match state {
            SupervisorRecoveryState::PayloadPrepared {
                payload,
                registration_nonce,
            } => {
                entry.record.state = SupervisorRecoveryState::PayloadRegistered {
                    payload,
                    registration_nonce,
                };
                self.persist_transition(worker_id, "payload_registered")?;
                Ok(())
            }
            state => {
                entry.record.state = state;
                Err(SessionError::WorkerProtocolFailed)
            }
        }
    }
}

impl SupervisorLoopState {
    pub(super) fn persist_transition(
        &self,
        lifecycle_id: &str,
        state: &str,
    ) -> Result<(), SessionError> {
        let Some(ledger) = &self.ledger else {
            return Ok(());
        };
        ledger
            .lock()
            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?
            .transition(lifecycle_id, state)
            .map_err(|_| SessionError::PersistentRecoveryUnavailable)
    }

    pub(super) fn persist_resolve(&self, lifecycle_id: &str) -> Result<(), SessionError> {
        let Some(ledger) = &self.ledger else {
            return Ok(());
        };
        ledger
            .lock()
            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?
            .resolve_and_remove(lifecycle_id)
            .map_err(|_| SessionError::PersistentRecoveryUnavailable)
    }
}

fn persist_new_record_to(
    ledger: &Option<Arc<Mutex<PersistentRecoveryLedger>>>,
    record: PersistentRecoveryRecord,
) -> Result<(), SessionError> {
    let Some(ledger) = ledger else {
        return Ok(());
    };
    ledger
        .lock()
        .map_err(|_| SessionError::PersistentRecoveryUnavailable)?
        .create(record)
        .map_err(|_| SessionError::PersistentRecoveryUnavailable)
}
