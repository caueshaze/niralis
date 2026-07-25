use super::*;
use crate::launcher::recovery_admin_host::{LinuxRecoveryAdminHost, RecoveryAdminHostRef};

mod messages;
mod pending;
mod release;
mod running;
mod running_control;
pub(super) mod support;
mod terminal_vt;
use running::RunningRegistration;
use support::*;
mod admin;
mod admin_support;
use tracing::info;

pub(super) struct SupervisorLoopState {
    children: Vec<SupervisedWorker>,
    pending: Vec<PendingWorkerLifecycle>,
    quarantined: Vec<SupervisorSessionRecoveryRecord>,
    seat: SeatLifecycle,
    recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
    recovery_admin_host: RecoveryAdminHostRef,
    ledger: Option<Arc<Mutex<PersistentRecoveryLedger>>>,
}

impl SupervisorLoopState {
    fn new(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
        recovery_admin_host: RecoveryAdminHostRef,
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
            recovery_admin_host,
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

/// Test-only entry point used by the root sacrificial-VT harness.  It invokes
/// the same administrative coordinator as the recovery socket, while the host
/// implementation is supplied by the test instead of Linux production I/O.
#[cfg(all(test, feature = "vt-integration-tests"))]
pub(crate) fn dispatch_recovery_admin_for_test(
    ledger: PersistentRecoveryLedger,
    host: RecoveryAdminHostRef,
    request: crate::RecoveryAdminRequest,
) -> (crate::RecoveryAdminResponse, bool, PersistentRecoveryLedger) {
    let ledger = Arc::new(Mutex::new(ledger));
    let mut state = SupervisorLoopState::new(
        Arc::new(LinuxSupervisorRecoveryProvider),
        host,
        Some(ledger.clone()),
    );
    let response = state.recovery_admin(request).expect("fixture coordinator");
    let published_free = matches!(state.seat, SeatLifecycle::Free);
    drop(state);
    let ledger = Arc::try_unwrap(ledger)
        .expect("fixture ledger sole owner")
        .into_inner()
        .expect("fixture ledger mutex");
    (response, published_free, ledger)
}

impl WorkerSupervisor {
    pub(super) fn new() -> Self {
        Self::new_with_recovery_provider(Arc::new(LinuxSupervisorRecoveryProvider))
    }

    pub(super) fn new_with_recovery_provider(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || {
            SupervisorLoopState::new(recovery_provider, Arc::new(LinuxRecoveryAdminHost), None)
                .run(receiver)
        });
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
            SupervisorLoopState::new(
                recovery_provider,
                Arc::new(LinuxRecoveryAdminHost),
                Some(ledger),
            )
            .run(receiver)
        });
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }

    #[cfg(all(test, feature = "supervisor-test-fixtures"))]
    pub(super) fn new_with_persistent_ledger_and_admin_host(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
        mut ledger: PersistentRecoveryLedger,
        recovery_admin_host: RecoveryAdminHostRef,
    ) -> Self {
        StartupRecoveryCoordinator::new(recovery_provider.as_ref()).reconcile(&mut ledger);
        let (sender, receiver) = mpsc::channel();
        let ledger = Arc::new(Mutex::new(ledger));
        let join = thread::spawn(move || {
            SupervisorLoopState::new(recovery_provider, recovery_admin_host, Some(ledger))
                .run(receiver)
        });
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }
}

#[cfg(all(test, feature = "supervisor-test-fixtures"))]
mod admin_host_construction_tests {
    use super::*;
    #[test]
    fn fixture_constructor_accepts_an_explicit_admin_host() {
        let _ = WorkerSupervisor::new_with_persistent_ledger_and_admin_host;
    }
}

#[cfg(all(test, feature = "supervisor-test-fixtures"))]
mod admin_tests;
