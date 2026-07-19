use super::*;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StartupReconciliationSummary {
    pub(crate) free: usize,
    pub(crate) quarantined: usize,
}

pub(crate) struct StartupRecoveryCoordinator<'a> {
    provider: &'a dyn SupervisorRecoveryProvider,
}

impl<'a> StartupRecoveryCoordinator<'a> {
    pub(crate) fn new(provider: &'a dyn SupervisorRecoveryProvider) -> Self {
        Self { provider }
    }

    pub(crate) fn reconcile(
        &self,
        ledger: &mut PersistentRecoveryLedger,
    ) -> StartupReconciliationSummary {
        let _ = startup_failure_catalog();
        let records = ledger.records().cloned().collect::<Vec<_>>();
        let unknown_scopes = self
            .provider
            .inventory_unknown_scopes(&records)
            .unwrap_or(UnknownScopeInventory::GlobalQuarantine);
        let blocked_seats = match unknown_scopes {
            UnknownScopeInventory::None => BTreeSet::new(),
            UnknownScopeInventory::KnownSeats(seats) => {
                for seat in &seats {
                    ledger.mark_seat_startup_quarantine(seat.clone());
                }
                seats
            }
            UnknownScopeInventory::GlobalQuarantine => {
                ledger.mark_startup_quarantine();
                return StartupReconciliationSummary {
                    free: 0,
                    quarantined: records.len().max(1),
                };
            }
        };
        let conflicts = conflicts(&records);
        let mut summary = StartupReconciliationSummary::default();
        for record in records {
            if blocked_seats.contains(&record.seat) {
                quarantine_startup_record(
                    ledger,
                    &record.lifecycle_id,
                    StartupRecoveryFailure::UnknownPayloadScope,
                    &mut summary,
                );
                continue;
            }
            let relation = PersistentRecoveryLedger::boot_relation(&record);
            if matches!(
                record.state.as_str(),
                "record_resolved" | "cleared_by_boot_boundary"
            ) {
                if ledger.remove_resolved(&record.lifecycle_id).is_ok() {
                    summary.free += 1;
                } else {
                    quarantine_startup_record(
                        ledger,
                        &record.lifecycle_id,
                        StartupRecoveryFailure::UnsupportedRehydration,
                        &mut summary,
                    );
                }
                continue;
            }
            if relation == RecoveryBootRelation::SameBoot
                && conflicts.contains(&record.lifecycle_id)
            {
                quarantine_startup_record(
                    ledger,
                    &record.lifecycle_id,
                    StartupRecoveryFailure::PersistentRecordConflict,
                    &mut summary,
                );
                continue;
            }
            if relation == RecoveryBootRelation::SameBoot
                && matches!(
                    persisted_decision(&record),
                    StartupRecoveryDecision::PreserveQuarantine
                )
                && !can_retry_coherent_absent_boundary(&record)
            {
                summary.quarantined += 1;
                continue;
            }
            if can_retry_coherent_absent_boundary(&record) {
                info!(
                    lifecycle_id = %record.lifecycle_id,
                    "retrying coherent absent-boundary proof after startup identity quarantine"
                );
            }
            let decision = match self.provider.reconcile_startup(&record, relation, ledger) {
                StartupRecoveryOutcome::Free => match relation {
                    RecoveryBootRelation::SameBoot => {
                        StartupRecoveryDecision::ResumeAfterBoundaryProof
                    }
                    RecoveryBootRelation::PreviousBoot => {
                        StartupRecoveryDecision::ClearPreviousBootRecord
                    }
                },
                StartupRecoveryOutcome::Quarantined(reason) => {
                    StartupRecoveryDecision::Quarantine(reason)
                }
            };
            match decision {
                StartupRecoveryDecision::ResumeAfterBoundaryProof => {
                    if ledger.resolve_and_remove(&record.lifecycle_id).is_ok() {
                        summary.free += 1;
                    } else {
                        quarantine_startup_record(
                            ledger,
                            &record.lifecycle_id,
                            StartupRecoveryFailure::UnsupportedRehydration,
                            &mut summary,
                        );
                    }
                }
                StartupRecoveryDecision::ClearPreviousBootRecord => {
                    if ledger
                        .clear_previous_boot_record(&record.lifecycle_id)
                        .is_ok()
                    {
                        summary.free += 1;
                    } else {
                        quarantine_startup_record(
                            ledger,
                            &record.lifecycle_id,
                            StartupRecoveryFailure::PreviousBootConflict,
                            &mut summary,
                        );
                    }
                }
                StartupRecoveryDecision::Quarantine(reason) => {
                    quarantine_startup_record(ledger, &record.lifecycle_id, reason, &mut summary)
                }
                _ => quarantine_startup_record(
                    ledger,
                    &record.lifecycle_id,
                    StartupRecoveryFailure::UnsupportedRehydration,
                    &mut summary,
                ),
            }
        }
        info!(
            free_seats = summary.free,
            quarantined_seats = summary.quarantined,
            "startup reconciliation complete"
        );
        summary
    }
}

fn persisted_decision(record: &PersistentRecoveryRecord) -> StartupRecoveryDecision {
    match record.state.as_str() {
        "started" | "worker_exited_unexpectedly" => {
            StartupRecoveryDecision::ResumeEmergencyRecovery
        }
        "payload_boundary_proven_empty" => StartupRecoveryDecision::ResumeLogindCleanup,
        "logind_cleanup_completed" => StartupRecoveryDecision::ResumeVtRecovery,
        "vt_recovery_completed" => StartupRecoveryDecision::ResumeAfterBoundaryProof,
        "quarantined" | "vt_disallocate_failed_busy" => StartupRecoveryDecision::PreserveQuarantine,
        "payload_prepared" | "payload_registered" => {
            StartupRecoveryDecision::ObserveSurvivingWorker
        }
        _ => StartupRecoveryDecision::Quarantine(StartupRecoveryFailure::UnsupportedRehydration),
    }
}

fn startup_failure_catalog() -> [StartupRecoveryFailure; 11] {
    [
        StartupRecoveryFailure::PersistentRecordConflict,
        StartupRecoveryFailure::BoundaryIdentityChanged,
        StartupRecoveryFailure::WorkerIdentityIndeterminate,
        StartupRecoveryFailure::LeaderIdentityIndeterminate,
        StartupRecoveryFailure::LogindOwnerChanged,
        StartupRecoveryFailure::LogindIdentityChanged,
        StartupRecoveryFailure::UnknownPayloadScope,
        StartupRecoveryFailure::SystemdOwnerChanged,
        StartupRecoveryFailure::PreviousBootConflict,
        StartupRecoveryFailure::UnsupportedRehydration,
        StartupRecoveryFailure::VtDisallocateBusy,
    ]
}

fn conflicts(records: &[PersistentRecoveryRecord]) -> BTreeSet<String> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut conflicted = BTreeSet::new();
    for record in records {
        for key in [
            format!("seat:{}", record.seat),
            record
                .target_vt
                .map_or_else(String::new, |vt| format!("vt:{vt}")),
            record
                .invocation_id
                .as_ref()
                .map_or_else(String::new, |id| format!("invocation:{id}")),
        ] {
            if key.is_empty() {
                continue;
            }
            if let Some(previous) = seen.insert(key, record.lifecycle_id.clone()) {
                conflicted.insert(previous);
                conflicted.insert(record.lifecycle_id.clone());
            }
        }
    }
    conflicted
}
