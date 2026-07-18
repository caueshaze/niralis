use super::*;

mod pending;
mod release;
mod running;
pub(super) mod support;
use running::RunningRegistration;
use support::*;

pub(super) struct SupervisorLoopState {
    children: Vec<SupervisedWorker>,
    pending: Vec<PendingWorkerLifecycle>,
    quarantined: Vec<SupervisorSessionRecoveryRecord>,
    seat: SeatLifecycle,
    recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
}

impl SupervisorLoopState {
    fn new(recovery_provider: Arc<dyn SupervisorRecoveryProvider>) -> Self {
        Self {
            children: Vec::new(),
            pending: Vec::new(),
            quarantined: Vec::new(),
            seat: SeatLifecycle::Free,
            recovery_provider,
        }
    }

    fn run(mut self, receiver: mpsc::Receiver<WorkerSupervisorMessage>) {
        loop {
            match receiver.recv_timeout(Duration::from_millis(25)) {
                Ok(WorkerSupervisorMessage::Shutdown) => {
                    shutdown_workers(&mut self.children);
                    break;
                }
                Ok(message) => self.handle_message(message),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    shutdown_workers(&mut self.children);
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            self.reap_exited_workers();
            let _ = (&self.seat, self.quarantined.len());
        }
    }

    fn handle_message(&mut self, message: WorkerSupervisorMessage) {
        match message {
            WorkerSupervisorMessage::ReserveSeat { worker_id, result } => {
                let _ = result.send(self.reserve_seat(worker_id));
            }
            WorkerSupervisorMessage::CancelSeatReservation { worker_id } => {
                self.cancel_seat_reservation(&worker_id);
            }
            WorkerSupervisorMessage::BeginPending {
                worker_id,
                worker_pid,
                launcher_pid,
                session,
                child,
                previous_vt,
                result,
            } => {
                let _ = result.send(self.begin_pending(
                    worker_id,
                    worker_pid,
                    launcher_pid,
                    session,
                    child,
                    previous_vt,
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
                worker_id,
                expected_clean,
                worker_exit_status,
                result,
            } => {
                let _ =
                    result.send(self.abort_pending(worker_id, expected_clean, worker_exit_status));
            }
            WorkerSupervisorMessage::Register {
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
                result,
            } => {
                let _ = result.send(self.register_running(RunningRegistration {
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
                }));
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

impl WorkerSupervisor {
    pub(super) fn new() -> Self {
        Self::new_with_recovery_provider(Arc::new(LinuxSupervisorRecoveryProvider))
    }

    pub(super) fn new_with_recovery_provider(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || SupervisorLoopState::new(recovery_provider).run(receiver));
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }
}
