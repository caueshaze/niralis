use super::admission::AdmissionRollbackLease;
use super::*;
use tracing::{debug, warn};

pub(super) struct RunningRegistration {
    pub(super) admission_transaction: crate::launcher::login_transaction::PendingLaunchTransaction,
    pub(super) runtime_id: RuntimeSessionId,
    pub(super) supervisor_channel: UnixStream,
    #[cfg(any(
        test,
        feature = "integration-test-control",
        feature = "supervisor-test-fixtures"
    ))]
    pub(super) fixture_supervisor_transport:
        Option<crate::worker_attempt::FixtureSupervisorTransportHandle>,
    #[cfg(any(
        test,
        feature = "integration-test-control",
        feature = "supervisor-test-fixtures"
    ))]
    pub(super) fixture_inherited_supervisor_control: bool,
    pub(super) session: StartedSession,
    pub(super) session_pid: u32,
    pub(super) session_pgid: u32,
    pub(super) worker_id: String,
    pub(super) logind_session_id: crate::LogindSessionId,
    pub(super) payload_scope: crate::PayloadScopeIdentity,
    pub(super) registration_nonce: String,
    pub(super) control_path: PathBuf,
    pub(super) control_dir: TempDir,
    pub(super) control_sender: mpsc::Sender<WorkerSupervisorMessage>,
}

impl SupervisorLoopState {
    pub(super) fn register_running(
        &mut self,
        registration: RunningRegistration,
    ) -> Result<(), SessionError> {
        let RunningRegistration {
            mut admission_transaction,
            runtime_id,
            supervisor_channel,
            #[cfg(any(
                test,
                feature = "integration-test-control",
                feature = "supervisor-test-fixtures"
            ))]
            fixture_supervisor_transport,
            #[cfg(any(
                test,
                feature = "integration-test-control",
                feature = "supervisor-test-fixtures"
            ))]
            fixture_inherited_supervisor_control,
            session,
            session_pid,
            session_pgid,
            worker_id,
            logind_session_id,
            payload_scope,
            registration_nonce,
            control_path,
            control_dir,
            control_sender,
        } = registration;
        let lifecycle_id = admission_transaction.lifecycle_id().to_owned();
        if lifecycle_id != worker_id {
            return Err(SessionError::WorkerProtocolFailed);
        }
        let index = self.pending.iter().position(|entry| {
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
        });
        let Some(index) = index else {
            let _ = self.admission.cancel(AdmissionRollbackLease::Pending(
                admission_transaction.pending_lease()?,
            ));
            return Err(SessionError::WorkerProtocolFailed);
        };
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
            let _ = self.admission.enter_quarantine_from_pending(
                admission_transaction.pending_lease()?,
                EmergencyRecoveryStage::RecoveryRecordValidation,
                SupervisorRecoveryError::InvalidRecord,
            );
            self.quarantined.push(entry.record);
            kill_shared_worker(&entry.child);
            return Err(SessionError::WorkerProtocolFailed);
        }
        entry.record.state = SupervisorRecoveryState::Started {
            payload,
            runtime_id,
        };
        self.persist_transition(&worker_id, "started")?;
        info!(worker_id, "worker reached durable started state");
        let recovery = self.recovery_admission_state("seat0");
        let receipt = admission_transaction.commit(&mut self.admission, recovery)?;
        let admission = self.admission.promote_committed_to_running(receipt)?;
        self.children.push(SupervisedWorker {
            admission,
            record: entry.record,
            child: entry.child,
            supervisor_channel,
            #[cfg(any(
                test,
                feature = "integration-test-control",
                feature = "supervisor-test-fixtures"
            ))]
            fixture_supervisor_transport,
            #[cfg(any(
                test,
                feature = "integration-test-control",
                feature = "supervisor-test-fixtures"
            ))]
            fixture_inherited_supervisor_control,
            session,
            session_pid,
            session_pgid,
            worker_id: worker_id.clone(),
            registration_nonce,
            control_path,
            _control_dir: control_dir,
            terminal_vt_reported_busy: false,
        });
        let reader = self
            .children
            .last()
            .expect("just pushed")
            .supervisor_channel
            .try_clone()
            .map_err(|_| SessionError::WorkerIoFailed)?;
        super::running_control::spawn_running_control_reader(reader, control_sender);
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
}

include!("running/exit_handling.rs");
