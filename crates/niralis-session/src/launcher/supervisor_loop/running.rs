use super::*;
use tracing::{debug, warn};

pub(super) struct RunningRegistration {
    pub(super) runtime_id: RuntimeSessionId,
    pub(super) supervisor_channel: UnixStream,
    pub(super) session: StartedSession,
    pub(super) session_pid: u32,
    pub(super) session_pgid: u32,
    pub(super) worker_id: String,
    pub(super) logind_session_id: crate::LogindSessionId,
    pub(super) payload_scope: crate::PayloadScopeIdentity,
    pub(super) control_path: PathBuf,
    pub(super) control_dir: TempDir,
}

impl SupervisorLoopState {
    pub(super) fn register_running(
        &mut self,
        registration: RunningRegistration,
    ) -> Result<(), SessionError> {
        let RunningRegistration {
            runtime_id,
            supervisor_channel,
            session,
            session_pid,
            session_pgid,
            worker_id,
            logind_session_id,
            payload_scope,
            control_path,
            control_dir,
        } = registration;
        let index = self
            .pending
            .iter()
            .position(|entry| {
                entry.record.lifecycle_id == worker_id
                    && entry.record.worker_pid
                        == entry.child.lock().ok().map(|child| child.id()).unwrap_or(0)
                    && entry.record.payload_identity() == Some(&payload_scope)
                    && matches!(entry.release, PendingReleaseState::NotRequested)
                    && !entry.terminal_before_started
                    && matches!(
                        entry.record.state,
                        SupervisorRecoveryState::PayloadRegistered { .. }
                    )
            })
            .ok_or(SessionError::WorkerProtocolFailed)?;
        let mut entry = self.pending.swap_remove(index);
        let state = entry.record.take_state_for_transition();
        let SupervisorRecoveryState::PayloadRegistered { payload, .. } = state else {
            unreachable!("registration predicate checked state")
        };
        if payload.logind.id != logind_session_id || payload.boundary.leader_pid() != session_pid {
            entry.record.state = SupervisorRecoveryState::Quarantined {
                stage: EmergencyRecoveryStage::RecoveryRecordValidation,
                reason: SupervisorRecoveryError::InvalidRecord,
                retained_identity: SupervisorRetainedRecoveryIdentity::Payload {
                    payload: Box::new(payload),
                },
            };
            self.seat = SeatLifecycle::Quarantined {
                lifecycle_id: worker_id,
                stage: EmergencyRecoveryStage::RecoveryRecordValidation,
                reason: SupervisorRecoveryError::InvalidRecord,
            };
            self.quarantined.push(entry.record);
            kill_shared_worker(&entry.child);
            return Err(SessionError::WorkerProtocolFailed);
        }
        entry.record.state = SupervisorRecoveryState::Started {
            payload,
            runtime_id,
        };
        self.children.push(SupervisedWorker {
            record: entry.record,
            child: entry.child,
            _supervisor_channel: supervisor_channel,
            session,
            session_pid,
            session_pgid,
            worker_id,
            control_path,
            _control_dir: control_dir,
        });
        Ok(())
    }

    pub(super) fn terminate_running(
        &mut self,
        session: StartedSession,
        runtime_id: Option<RuntimeSessionId>,
    ) -> Result<(), SessionError> {
        self.children
            .iter_mut()
            .find(|worker| {
                runtime_id.as_ref().map_or(worker.session == session, |id| {
                    record_runtime_id(&worker.record) == Some(id)
                })
            })
            .map(request_worker_termination)
            .unwrap_or(Ok(()))
    }

    pub(super) fn reap_exited_workers(&mut self) {
        let mut index = 0;
        while index < self.children.len() {
            let status = self.children[index]
                .child
                .lock()
                .map_err(|_| SessionError::WorkerIoFailed)
                .and_then(|mut child| child.try_wait().map_err(|_| SessionError::WorkerIoFailed));
            match status {
                Ok(Some(status)) => self.finish_exited_worker(index, status),
                Ok(None) => index += 1,
                Err(error) => {
                    debug!(?error, "failed to inspect session worker");
                    index += 1;
                }
            }
        }
    }

    pub(super) fn finish_exited_worker(&mut self, index: usize, status: ExitStatus) {
        let mut worker = self.children.swap_remove(index);
        if status.success()
            && finalize_clean_worker_exit(
                &mut worker.record,
                status,
                self.recovery_provider.as_ref(),
            )
            .is_ok()
        {
            debug!(?status, username = %worker.session.username, session_pid = worker.session_pid, "session worker exited and was reaped after verified clean finalization");
            self.seat = SeatLifecycle::Free;
            return;
        }
        warn!(worker_pid = worker.record.worker_pid, status = %exit_status_label(status), phase = worker.record.phase_name(), session = %worker.record.session_name, username = %worker.record.requested_username, "session worker exited unexpectedly");
        let classification = mark_worker_exited_unexpectedly(&mut worker.record, status);
        self.seat = SeatLifecycle::Recovering {
            lifecycle_id: worker.record.lifecycle_id.clone(),
            phase: worker.record.phase_name(),
            reason: classification,
        };
        match SupervisorEmergencyRecoveryCoordinator::new(self.recovery_provider.as_ref())
            .recover(&mut worker.record, status)
        {
            outcome @ SupervisorEmergencyRecoveryOutcome::Recovered { .. } => {
                worker.record.state = SupervisorRecoveryState::Recovered { outcome };
                self.seat = SeatLifecycle::Free;
            }
            SupervisorEmergencyRecoveryOutcome::Quarantined { stage, reason } => {
                worker.record.quarantine(stage, reason.clone());
                self.seat = SeatLifecycle::Quarantined {
                    lifecycle_id: worker.record.lifecycle_id.clone(),
                    stage,
                    reason,
                };
                self.quarantined.push(worker.record);
            }
        }
    }
}
