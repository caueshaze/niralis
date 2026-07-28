use super::*;
use crate::launcher::recovery_admin_host::{LinuxRecoveryAdminHost, RecoveryAdminHostRef};

mod construction;
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
mod admin_finalization;
mod admin_support;
pub(super) mod admission;
#[cfg(test)]
mod admission_tests;
use admission::{RecoveryAdmissionState, SeatAdmissionController};
use tracing::info;

pub(super) struct SupervisorLoopState {
    children: Vec<SupervisedWorker>,
    pending: Vec<PendingWorkerLifecycle>,
    quarantined: Vec<SupervisorSessionRecoveryRecord>,
    admission: SeatAdmissionController,
    recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
    recovery_admin_host: RecoveryAdminHostRef,
    ledger: Option<Arc<Mutex<PersistentRecoveryLedger>>>,
    precommit_store: Option<Arc<Mutex<PreCommitRuntimeStore>>>,
}

impl SupervisorLoopState {
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
            let _ = self.quarantined.len();
        }
    }
}

impl SupervisorLoopState {
    pub(super) fn recovery_admission_state(&self, seat: &str) -> RecoveryAdmissionState {
        let Some(ledger) = &self.ledger else {
            return RecoveryAdmissionState::Clear;
        };
        let Ok(ledger) = ledger.lock() else {
            return RecoveryAdmissionState::GloballyBlocked {
                reason: "recovery_ledger_unavailable",
            };
        };
        if ledger.startup_quarantined() || ledger.record_set_classification().global_quarantine {
            return RecoveryAdmissionState::GloballyBlocked {
                reason: "recovery_global_quarantine",
            };
        }
        if let Some(store) = &self.precommit_store {
            let Ok(store) = store.lock() else {
                return RecoveryAdmissionState::GloballyBlocked {
                    reason: "precommit_runtime_unavailable",
                };
            };
            if store.startup_quarantined() {
                return RecoveryAdmissionState::GloballyBlocked {
                    reason: "precommit_runtime_quarantine",
                };
            }
            if store.seat_startup_quarantined(seat) {
                return RecoveryAdmissionState::SeatBlocked {
                    seat: seat.to_owned(),
                    reason: "precommit_runtime_seat_blocked",
                };
            }
        }
        if ledger.seat_startup_quarantined(seat)
            || ledger.record_set_classification().seat_blocked(seat)
        {
            return RecoveryAdmissionState::SeatBlocked {
                seat: seat.to_owned(),
                reason: "recovery_seat_blocked",
            };
        }
        RecoveryAdmissionState::Clear
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
        None,
    );
    let response = state.recovery_admin(request).expect("fixture coordinator");
    let published_free = state.admission.is_free();
    drop(state);
    let ledger = Arc::try_unwrap(ledger)
        .expect("fixture ledger sole owner")
        .into_inner()
        .expect("fixture ledger mutex");
    (response, published_free, ledger)
}

#[cfg(all(test, feature = "supervisor-test-fixtures"))]
mod admin_tests;
