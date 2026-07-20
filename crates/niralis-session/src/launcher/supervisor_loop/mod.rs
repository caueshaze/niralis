use super::*;

mod messages;
mod pending;
mod release;
mod running;
mod running_control;
pub(super) mod support;
mod terminal_vt;
use running::RunningRegistration;
use support::*;
use tracing::info;

pub(super) struct SupervisorLoopState {
    children: Vec<SupervisedWorker>,
    pending: Vec<PendingWorkerLifecycle>,
    quarantined: Vec<SupervisorSessionRecoveryRecord>,
    seat: SeatLifecycle,
    recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
    ledger: Option<Arc<Mutex<PersistentRecoveryLedger>>>,
}

impl SupervisorLoopState {
    fn new(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
        ledger: Option<Arc<Mutex<PersistentRecoveryLedger>>>,
    ) -> Self {
        if let Some(record) = ledger
            .as_ref()
            .and_then(|value| value.lock().ok())
            .and_then(|value| value.records().next().cloned())
        {
            let reconciling = SeatLifecycle::Reconciling {
                lifecycle_id: record.lifecycle_id,
                stage: "startup_reconciliation",
            };
            info!(?reconciling, "seat entered startup reconciliation");
        }
        let seat = ledger
            .as_ref()
            .and_then(|ledger| ledger.lock().ok())
            .and_then(|ledger| {
                ledger
                    .records()
                    .next()
                    .map(|record| {
                        match PersistentRecoveryLedger::boot_relation(record) {
                            RecoveryBootRelation::SameBoot => {
                                info!(lifecycle_id = %record.lifecycle_id, "recovery record belongs to current boot");
                            }
                            RecoveryBootRelation::PreviousBoot => {
                                info!(lifecycle_id = %record.lifecycle_id, "recovery record belongs to previous boot");
                            }
                        }
                        SeatLifecycle::Quarantined {
                            lifecycle_id: record.lifecycle_id.clone(),
                            stage: EmergencyRecoveryStage::RecoveryRecordValidation,
                            reason: SupervisorRecoveryError::from_persistent_quarantine(
                                record.quarantine_reason.as_deref(),
                                &record.state,
                            ),
                        }
                    })
                    .or_else(|| {
                        ledger
                            .startup_quarantined()
                            .then(|| SeatLifecycle::Quarantined {
                                lifecycle_id: "startup-quarantine".to_owned(),
                                stage: EmergencyRecoveryStage::RecoveryRecordValidation,
                                reason: SupervisorRecoveryError::UnknownPayloadScope,
                            })
                            .or_else(|| {
                                ledger
                                    .seat_startup_quarantined("seat0")
                                    .then(|| SeatLifecycle::Quarantined {
                                    lifecycle_id: "unknown-payload-seat0".to_owned(),
                                    stage: EmergencyRecoveryStage::RecoveryRecordValidation,
                                    reason: SupervisorRecoveryError::UnknownPayloadScope,
                                    })
                            })
                    })
            })
            .unwrap_or(SeatLifecycle::Free);
        Self {
            children: Vec::new(),
            pending: Vec::new(),
            quarantined: Vec::new(),
            seat,
            recovery_provider,
            ledger,
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
}

impl WorkerSupervisor {
    pub(super) fn new() -> Self {
        Self::new_with_recovery_provider(Arc::new(LinuxSupervisorRecoveryProvider))
    }

    pub(super) fn new_with_recovery_provider(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let join =
            thread::spawn(move || SupervisorLoopState::new(recovery_provider, None).run(receiver));
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }

    pub(super) fn new_with_persistent_ledger(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
        mut ledger: PersistentRecoveryLedger,
    ) -> Self {
        StartupRecoveryCoordinator::new(recovery_provider.as_ref()).reconcile(&mut ledger);
        let (sender, receiver) = mpsc::channel();
        let ledger = Arc::new(Mutex::new(ledger));
        let join = thread::spawn(move || {
            SupervisorLoopState::new(recovery_provider, Some(ledger)).run(receiver)
        });
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }
}
