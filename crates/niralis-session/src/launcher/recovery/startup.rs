use super::*;
use std::collections::{BTreeMap, BTreeSet};
#[path = "startup_previous_boot.rs"]
mod startup_previous_boot;
#[path = "startup_support.rs"]
mod startup_support;
use startup_previous_boot::{log_previous_boot_plan, previous_boot_current_facts};
use startup_support::{conflicts, persisted_decision, startup_failure_catalog};
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
        tracing::debug!(
            typed_record_results = ledger.read_results().len(),
            "durable recovery records classified"
        );
        let inspection_host = LinuxPreviousBootInspectionHost;
        let current_boot = match inspection_host.current_boot_identity() {
            Ok(boot) => boot,
            Err(error) => {
                warn!(
                    ?error,
                    "previous-boot reconciliation cannot read current boot identity"
                );
                ledger.mark_startup_quarantine();
                return StartupReconciliationSummary {
                    free: 0,
                    quarantined: records.len().max(1),
                };
            }
        };
        let epochs = records
            .iter()
            .cloned()
            .map(|record| RecoveryRecordEpoch::classify(record, current_boot.clone()))
            .collect::<Result<Vec<_>, _>>();
        let epochs = match epochs {
            Ok(epochs) => epochs,
            Err(error) => {
                warn!(?error, "malformed recovery record boot identity");
                ledger.mark_startup_quarantine();
                return StartupReconciliationSummary {
                    free: 0,
                    quarantined: records.len().max(1),
                };
            }
        };
        let same_boot_records = epochs
            .iter()
            .filter_map(|epoch| match epoch {
                RecoveryRecordEpoch::SameBoot(record) => Some(record.record.clone()),
                RecoveryRecordEpoch::PreviousBoot(_) => None,
            })
            .collect::<Vec<_>>();
        let unknown_scopes = self
            .provider
            .inventory_unknown_scopes(&same_boot_records)
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
        let conflicts = conflicts(&same_boot_records);
        let record_set = ledger.record_set_classification().clone();
        if record_set.global_quarantine {
            warn!(
                typed_results = ledger.read_results().len(),
                "malformed_history; durable record set is globally quarantined"
            );
            ledger.mark_startup_quarantine();
            return StartupReconciliationSummary {
                free: 0,
                quarantined: records.len().max(1),
            };
        }
        let mut summary = StartupReconciliationSummary::default();
        for epoch in epochs {
            let same_boot = match epoch {
                RecoveryRecordEpoch::PreviousBoot(record) => {
                    if record_set.global_quarantine || record_set.seat_blocked(&record.record.seat)
                    {
                        ledger.mark_seat_startup_quarantine(record.record.seat.clone());
                        summary.quarantined += 1;
                        continue;
                    }
                    let facts = previous_boot_current_facts(
                        &inspection_host,
                        &record,
                        &records,
                        ledger.startup_quarantined(),
                    );
                    let plan = plan_previous_boot_reconciliation(&record, &facts);
                    log_previous_boot_plan(&record, &plan);
                    ledger.mark_seat_startup_quarantine(record.record.seat.clone());
                    match execute_previous_boot_plan(
                        ledger,
                        &inspection_host,
                        &record,
                        &facts,
                        &plan,
                    ) {
                        Ok(PreviousBootFinalizationOutcome::SeatFreed) => {
                            summary.free += 1;
                            info!(
                                lifecycle_id = %record.record.lifecycle_id,
                                "previous_boot historical finalization completed"
                            );
                        }
                        Ok(PreviousBootFinalizationOutcome::PreservedQuarantine) | Err(_) => {
                            summary.quarantined += 1;
                        }
                    }
                    continue;
                }
                RecoveryRecordEpoch::SameBoot(record) => record,
            };
            let record = same_boot.record.clone();
            // An administrative intent is evidence of an ioctl whose outcome
            // was not durably recorded. Startup must never repeat it.
            if let Some(attempt) = record.vt_recovery_attempts.last() {
                if matches!(
                    attempt.state,
                    crate::VtRecoveryAttemptState::IntentPersisted
                ) {
                    let _ = ledger.finish_vt_recovery_attempt(
                        &record.lifecycle_id,
                        attempt.attempt_id,
                        crate::VtRecoveryAttemptState::Indeterminate,
                        None,
                    );
                    summary.quarantined += 1;
                    continue;
                }
            }
            if blocked_seats.contains(&record.seat) {
                quarantine_startup_record(
                    ledger,
                    &record.lifecycle_id,
                    StartupRecoveryFailure::UnknownPayloadScope,
                    &mut summary,
                );
                continue;
            }
            if matches!(
                record.state.as_str(),
                "record_resolved" | "cleared_by_boot_boundary"
            ) {
                if ledger.finalize_startup_record(&record.lifecycle_id).is_ok() {
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
            if conflicts.contains(&record.lifecycle_id) {
                quarantine_startup_record(
                    ledger,
                    &record.lifecycle_id,
                    StartupRecoveryFailure::PersistentRecordConflict,
                    &mut summary,
                );
                continue;
            }
            if matches!(
                persisted_decision(&record),
                StartupRecoveryDecision::PreserveQuarantine
            ) && !can_retry_coherent_absent_boundary(&record)
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
            let decision = match self.provider.reconcile_startup(&same_boot, ledger) {
                StartupRecoveryOutcome::Free => StartupRecoveryDecision::ResumeAfterBoundaryProof,
                StartupRecoveryOutcome::Quarantined(reason) => {
                    StartupRecoveryDecision::Quarantine(reason)
                }
            };
            match decision {
                StartupRecoveryDecision::ResumeAfterBoundaryProof => {
                    if ledger.finalize_startup_record(&record.lifecycle_id).is_ok() {
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
        summary.free += resume_removed_previous_boot_finalization(ledger).unwrap_or_default();
        info!(
            free_seats = summary.free,
            quarantined_seats = summary.quarantined,
            "startup reconciliation complete"
        );
        summary
    }
}
