use super::*;

impl SupervisorLoopState {
    pub(super) fn new(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
        recovery_admin_host: RecoveryAdminHostRef,
        ledger: Option<Arc<Mutex<PersistentRecoveryLedger>>>,
        precommit_store: Option<Arc<Mutex<PreCommitRuntimeStore>>>,
    ) -> Self {
        let seat = ledger
            .as_ref()
            .and_then(|ledger| ledger.lock().ok())
            .map(|ledger| {
                let blocked = ledger.startup_quarantined()
                    || ledger.record_set_classification().global_quarantine
                    || ledger.seat_startup_quarantined("seat0")
                    || ledger.record_set_classification().seat_blocked("seat0");
                if blocked {
                    SeatLifecycle::Quarantined {
                        lifecycle_id: "consolidated-recovery-seat0".to_owned(),
                        stage: EmergencyRecoveryStage::RecoveryRecordValidation,
                        reason: SupervisorRecoveryError::UnknownPayloadScope,
                    }
                } else {
                    SeatLifecycle::Free
                }
            })
            .unwrap_or(SeatLifecycle::Free);
        Self {
            children: Vec::new(),
            pending: Vec::new(),
            quarantined: Vec::new(),
            admission: SeatAdmissionController::new("seat0", seat),
            recovery_provider,
            recovery_admin_host,
            ledger,
            precommit_store,
        }
    }
}

impl WorkerSupervisor {
    pub(in crate::launcher) fn new() -> Self {
        Self::new_with_recovery_provider(Arc::new(LinuxSupervisorRecoveryProvider))
    }

    pub(in crate::launcher) fn new_with_recovery_provider(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || {
            SupervisorLoopState::new(
                recovery_provider,
                Arc::new(LinuxRecoveryAdminHost),
                None,
                None,
            )
            .run(receiver)
        });
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }

    pub(in crate::launcher) fn new_with_persistent_ledger(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
        mut ledger: PersistentRecoveryLedger,
    ) -> Self {
        let precommit_store = open_precommit_store(&ledger);
        StartupRecoveryCoordinator::new(recovery_provider.as_ref()).reconcile(&mut ledger);
        let (sender, receiver) = mpsc::channel();
        let ledger = Arc::new(Mutex::new(ledger));
        if let Some(store) = &precommit_store {
            install_process_runtime_store(store.clone());
        }
        let join = thread::spawn(move || {
            SupervisorLoopState::new(
                recovery_provider,
                Arc::new(LinuxRecoveryAdminHost),
                Some(ledger),
                precommit_store,
            )
            .run(receiver)
        });
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }

    #[cfg(all(test, feature = "supervisor-test-fixtures"))]
    pub(in crate::launcher) fn new_with_persistent_ledger_and_admin_host(
        recovery_provider: Arc<dyn SupervisorRecoveryProvider>,
        mut ledger: PersistentRecoveryLedger,
        recovery_admin_host: RecoveryAdminHostRef,
    ) -> Self {
        let precommit_store = open_precommit_store(&ledger);
        StartupRecoveryCoordinator::new(recovery_provider.as_ref()).reconcile(&mut ledger);
        let (sender, receiver) = mpsc::channel();
        let ledger = Arc::new(Mutex::new(ledger));
        if let Some(store) = &precommit_store {
            install_process_runtime_store(store.clone());
        }
        let join = thread::spawn(move || {
            SupervisorLoopState::new(
                recovery_provider,
                recovery_admin_host,
                Some(ledger),
                precommit_store,
            )
            .run(receiver)
        });
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }
}

fn open_precommit_store(
    ledger: &PersistentRecoveryLedger,
) -> Option<Arc<Mutex<PreCommitRuntimeStore>>> {
    PreCommitRuntimeStore::open(
        DEFAULT_PRECOMMIT_RUNTIME_DIR,
        DEFAULT_PRECOMMIT_RUNTIME_LOCK,
    )
    .ok()
    .map(|mut store| {
        let _ = store.reconcile_startup(Some(ledger));
        Arc::new(Mutex::new(store))
    })
}

#[cfg(all(test, feature = "supervisor-test-fixtures"))]
mod construction_tests {
    use super::*;

    #[test]
    fn fixture_constructor_accepts_an_explicit_admin_host() {
        let _ = WorkerSupervisor::new_with_persistent_ledger_and_admin_host;
    }
}
