use super::*;

impl SupervisorLoopState {
    pub(super) fn handle_message(&mut self, message: WorkerSupervisorMessage) {
        match message {
            WorkerSupervisorMessage::ReserveSeat {
                lifecycle_id,
                result,
            } => {
                let _ = result.send(self.reserve_seat(lifecycle_id));
            }
            WorkerSupervisorMessage::CancelAdmission { lease } => {
                let _ = self.cancel_admission(lease);
            }
            WorkerSupervisorMessage::BeginPending {
                lease,
                worker_pid,
                launcher_pid,
                session,
                child,
                result,
            } => {
                let _ = result.send(self.begin_pending(
                    lease,
                    worker_pid,
                    launcher_pid,
                    session,
                    child,
                ));
            }
            WorkerSupervisorMessage::RecordPreparedScope {
                worker_id,
                worker_pid,
                session_pid,
                identity,
                registration_nonce,
                result,
            } => {
                let _ = result.send(self.record_prepared_scope(
                    worker_id,
                    worker_pid,
                    session_pid,
                    identity,
                    registration_nonce,
                ));
            }
            WorkerSupervisorMessage::MarkPayloadRegistered {
                worker_id,
                worker_pid,
                result,
            } => {
                let _ = result.send(self.mark_payload_registered(&worker_id, worker_pid));
            }
            WorkerSupervisorMessage::BeginRelease { request, result } => {
                let _ = result.send(self.begin_release(request));
            }
            WorkerSupervisorMessage::CompleteRelease {
                token,
                verification,
                result,
            } => {
                let _ = result.send(self.complete_release(token, verification));
            }
            WorkerSupervisorMessage::AbortPending {
                lease,
                expected_clean,
                worker_exit_status,
                result,
            } => {
                let _ = result.send(self.abort_pending(lease, expected_clean, worker_exit_status));
            }
            WorkerSupervisorMessage::Register {
                admission_transaction,
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
                result,
            } => {
                let _ = result.send(self.register_running(RunningRegistration {
                    admission_transaction: *admission_transaction,
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
                }));
            }
            WorkerSupervisorMessage::TerminalVtIntent {
                worker_id,
                worker_pid,
                registration_nonce,
                identity,
                result,
            } => {
                let _ = result.send(self.accept_terminal_vt_intent(
                    &worker_id,
                    worker_pid,
                    &registration_nonce,
                    &identity,
                ));
            }
            WorkerSupervisorMessage::TerminalVtResult {
                worker_id,
                worker_pid,
                registration_nonce,
                attempt_id,
                result: terminal_result,
                acknowledged,
            } => {
                let _ = acknowledged.send(self.accept_terminal_vt_result(
                    &worker_id,
                    worker_pid,
                    &registration_nonce,
                    attempt_id,
                    terminal_result,
                ));
            }
            WorkerSupervisorMessage::RecoveryAdmin { request, result } => {
                let _ = result.send(self.recovery_admin(request));
            }
            WorkerSupervisorMessage::Terminate {
                session,
                runtime_id,
                result,
            } => {
                let _ = result.send(self.terminate_running(session, runtime_id));
            }
            WorkerSupervisorMessage::Shutdown => unreachable!("run handles shutdown directly"),
        }
    }
}
