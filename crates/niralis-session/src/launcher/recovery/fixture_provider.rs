use super::*;
use std::collections::BTreeSet;

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
#[derive(Debug)]
pub(crate) struct SupervisorFixtureRecoveryProvider {
    pub(crate) mode: SupervisorFixtureBoundaryMode,
    pub(crate) counters: Arc<SupervisorFixtureCounters>,
    pub(crate) logind_already_gone: bool,
    pub(crate) vt_result: Result<(), SupervisorRecoveryError>,
    pub(crate) payload_members: Arc<Mutex<Vec<u32>>>,
    pub(crate) completion_event: Arc<OwnedFd>,
    pub(crate) prepare_gate_enabled: std::sync::atomic::AtomicBool,
    pub(crate) prepare_gate: Arc<OwnedFd>,
    pub(crate) operation_log: Option<std::path::PathBuf>,
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
impl SupervisorFixtureRecoveryProvider {
    pub(crate) fn successful() -> Self {
        let completion_event = fixture_eventfd().expect("fixture eventfd");
        let prepare_gate = fixture_eventfd().expect("fixture prepare gate eventfd");
        Self {
            mode: SupervisorFixtureBoundaryMode::AlreadyEmpty,
            counters: Arc::new(SupervisorFixtureCounters::default()),
            logind_already_gone: true,
            vt_result: Ok(()),
            payload_members: Arc::new(Mutex::new(Vec::new())),
            completion_event: Arc::new(completion_event),
            prepare_gate_enabled: std::sync::atomic::AtomicBool::new(false),
            prepare_gate: Arc::new(prepare_gate),
            operation_log: None,
        }
    }
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
impl SupervisorRecoveryProvider for SupervisorFixtureRecoveryProvider {
    fn inventory_unknown_scopes(
        &self,
        _records: &[PersistentRecoveryRecord],
    ) -> Result<UnknownScopeInventory, StartupRecoveryFailure> {
        let unknown = matches!(
            self.mode,
            SupervisorFixtureBoundaryMode::UnknownScope
                | SupervisorFixtureBoundaryMode::UnknownScopeKnownSeat
        );
        if unknown {
            fixture_event(self, "quarantine:unknown_scope");
        }
        if matches!(
            self.mode,
            SupervisorFixtureBoundaryMode::UnknownScopeKnownSeat
        ) {
            Ok(UnknownScopeInventory::KnownSeats(BTreeSet::from([
                "seat0".to_owned()
            ])))
        } else if unknown {
            Ok(UnknownScopeInventory::GlobalQuarantine)
        } else {
            Ok(UnknownScopeInventory::None)
        }
    }

    fn reconcile_startup(
        &self,
        record: &PersistentRecoveryRecord,
        relation: RecoveryBootRelation,
        ledger: &mut PersistentRecoveryLedger,
    ) -> StartupRecoveryOutcome {
        match relation {
            RecoveryBootRelation::PreviousBoot => StartupRecoveryOutcome::Free,
            RecoveryBootRelation::SameBoot => {
                fixture_event(self, "startup:same_boot");
                fixture_event(
                    self,
                    match self.mode {
                        SupervisorFixtureBoundaryMode::PayloadRecovered => "mode:payload_recovered",
                        SupervisorFixtureBoundaryMode::WorkerAliveHandoff => "mode:worker_alive",
                        SupervisorFixtureBoundaryMode::Replacement => "mode:replacement",
                        _ => "mode:other",
                    },
                );
                if matches!(
                    self.mode,
                    SupervisorFixtureBoundaryMode::RealSystemdOwnerChange
                        | SupervisorFixtureBoundaryMode::RealLogindOwnerChange
                ) {
                    return reconcile_real_owner_change(self.mode, self);
                }
                if let Some(outcome) = reconcile_fixture_dbus(self.mode, record, ledger, self) {
                    return outcome;
                }
                if let Some(failure) = fixture_owner_failure(self.mode) {
                    let watch = OwnerWatch::scripted();
                    watch.invalidate_for_test();
                    if watch.stable().is_err() {
                        fixture_event(self, "owner_change:invalidated");
                    }
                    return StartupRecoveryOutcome::Quarantined(failure);
                }
                if matches!(
                    record.operation_ledger.payload_kill,
                    DurableOperationState::IntentPersisted { .. }
                        | DurableOperationState::Indeterminate { .. }
                ) && !matches!(self.mode, SupervisorFixtureBoundaryMode::EmptyBoundary)
                {
                    fixture_event(self, "quarantine:indeterminate_payload_kill");
                    return StartupRecoveryOutcome::Quarantined(
                        StartupRecoveryFailure::BoundaryIdentityChanged,
                    );
                }
                match self.mode {
                    SupervisorFixtureBoundaryMode::Replacement => {
                        fixture_event(self, "quarantine:replacement");
                        StartupRecoveryOutcome::Quarantined(
                            StartupRecoveryFailure::BoundaryIdentityChanged,
                        )
                    }
                    SupervisorFixtureBoundaryMode::ScopeRecordConflict => {
                        fixture_event(self, "quarantine:scope_record_conflict");
                        StartupRecoveryOutcome::Quarantined(
                            StartupRecoveryFailure::PersistentRecordConflict,
                        )
                    }
                    SupervisorFixtureBoundaryMode::EbusyQuarantine => {
                        fixture_event(self, "quarantine:vt_ebusy");
                        StartupRecoveryOutcome::Quarantined(
                            StartupRecoveryFailure::UnsupportedRehydration,
                        )
                    }
                    SupervisorFixtureBoundaryMode::WorkerAliveHandoff => {
                        reconcile_fixture_worker(self, record, ledger);
                        StartupRecoveryOutcome::Free
                    }
                    SupervisorFixtureBoundaryMode::PayloadRecovered => {
                        if reconcile_fixture_payload(self, record, ledger) {
                            StartupRecoveryOutcome::Free
                        } else {
                            StartupRecoveryOutcome::Quarantined(
                                StartupRecoveryFailure::LeaderIdentityIndeterminate,
                            )
                        }
                    }
                    SupervisorFixtureBoundaryMode::AlreadyEmpty
                    | SupervisorFixtureBoundaryMode::EmptyBoundary
                    | SupervisorFixtureBoundaryMode::RestartReconciles => {
                        fixture_event(self, "proof:empty_boundary");
                        StartupRecoveryOutcome::Free
                    }
                    _ => StartupRecoveryOutcome::Quarantined(
                        StartupRecoveryFailure::UnsupportedRehydration,
                    ),
                }
            }
        }
    }

    fn capture_previous_vt(
        &self,
        seat: &str,
    ) -> Result<PreviousVtIdentity, SupervisorRecoveryError> {
        if seat == "seat0" {
            Ok(PreviousVtIdentity { number: 1 })
        } else {
            Err(SupervisorRecoveryError::VtIdentityChanged)
        }
    }

    fn prepare_payload(
        &self,
        identity: &crate::PayloadScopeIdentity,
        authoritative_leader_pid: u32,
        _worker_pid: u32,
        _launcher_pid: u32,
        previous_vt: &PreviousVtIdentity,
    ) -> Result<SupervisorPreparedPayload, SupervisorRecoveryError> {
        prepare_fixture_payload(self, identity, authoritative_leader_pid, previous_vt)
    }

    fn recover_pre_payload(
        &self,
        _worker_pid: u32,
        _expected_username: &str,
        _session_name: &str,
        _previous_vt: &PreviousVtIdentity,
    ) -> Result<SupervisorPrePayloadRecoveryResult, SupervisorRecoveryError> {
        Err(SupervisorRecoveryError::InvalidRecord)
    }

    fn cleanup_logind(
        &self,
        identity: &SupervisorLogindSessionIdentity,
    ) -> Result<SupervisorLogindCleanupResult, SupervisorRecoveryError> {
        use std::sync::atomic::Ordering;
        if self.logind_already_gone {
            fixture_event(self, "logind_already_gone");
            Ok(SupervisorLogindCleanupResult::AlreadyGone)
        } else {
            self.counters
                .logind_terminations
                .fetch_add(1, Ordering::SeqCst);
            fixture_event(
                self,
                &format!(
                    "logind_terminate id={} object_path={} seat={} vt={}",
                    identity.id.as_str(),
                    identity.object_path,
                    identity.seat,
                    identity.vt_number
                ),
            );
            Ok(SupervisorLogindCleanupResult::Removed)
        }
    }

    fn confirm_logind_absent(
        &self,
        _identity: &SupervisorLogindSessionIdentity,
    ) -> Result<bool, SupervisorRecoveryError> {
        Ok(self.logind_already_gone)
    }

    fn recover_vt(&self, _identity: &SupervisorVtIdentity) -> Result<(), SupervisorRecoveryError> {
        use std::sync::atomic::Ordering;
        self.counters.vt_recoveries.fetch_add(1, Ordering::SeqCst);
        fixture_event(self, "vt_recovery");
        let result = self.vt_result.clone();
        signal_fixture_completion(&self.completion_event);
        result
    }
}
