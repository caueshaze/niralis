use super::*;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PreCommitStartupSummary {
    pub(crate) cleared: usize,
    pub(crate) quarantined: usize,
}

impl PreCommitRuntimeStore {
    pub(crate) fn reconcile_startup(
        &mut self,
        ledger: Option<&PersistentRecoveryLedger>,
    ) -> PreCommitStartupSummary {
        let mut summary = PreCommitStartupSummary::default();
        let current_boot = match recovery::current_boot_id() {
            Ok(value) => value,
            Err(_) => {
                self.startup_quarantined = true;
                summary.quarantined = self.records.len().max(1);
                return summary;
            }
        };
        let records = self.records.values().cloned().collect::<Vec<_>>();
        for record in records {
            if record.boot_id != current_boot {
                summary.cleared += usize::from(
                    self.remove_record_by_id(&record.lifecycle_id).is_ok(),
                );
                if !self.records.contains_key(&record.lifecycle_id) {
                    continue;
                }
                self.startup_quarantined = true;
                summary.quarantined += 1;
                continue;
            }
            if record.handoff_committed && exact_a3_record_exists(ledger, &record) {
                if self.remove_record_by_id(&record.lifecycle_id).is_ok() {
                    summary.cleared += 1;
                } else {
                    self.startup_quarantined_seats.insert(record.seat.clone());
                    summary.quarantined += 1;
                }
                continue;
            }
            match inspect_worker_identity(&record) {
                WorkerIdentityStatus::Absent => clear_or_quarantine(self, &record, &mut summary),
                WorkerIdentityStatus::Exact => {
                    if kill_exact_pid(record.worker_pid.unwrap()).is_ok()
                        && self.remove_record_by_id(&record.lifecycle_id).is_ok()
                    {
                        summary.cleared += 1;
                    } else {
                        self.startup_quarantined_seats.insert(record.seat.clone());
                        summary.quarantined += 1;
                    }
                }
                WorkerIdentityStatus::Indeterminate => {
                    self.startup_quarantined_seats.insert(record.seat.clone());
                    summary.quarantined += 1;
                }
            }
        }
        if summary.quarantined > 0 {
            self.startup_quarantined = true;
        }
        summary
    }
}

fn exact_a3_record_exists(
    ledger: Option<&PersistentRecoveryLedger>,
    record: &PreCommitRuntimeRecord,
) -> bool {
    ledger
        .and_then(|ledger| {
            ledger.records().find(|a3| {
                a3.lifecycle_id == record.lifecycle_id
                    && a3.seat == record.seat
                    && a3.created_boot_id == record.boot_id
            })
        })
        .is_some()
}

fn clear_or_quarantine(
    store: &mut PreCommitRuntimeStore,
    record: &PreCommitRuntimeRecord,
    summary: &mut PreCommitStartupSummary,
) {
    if store.remove_record_by_id(&record.lifecycle_id).is_ok() {
        summary.cleared += 1;
    } else {
        store.startup_quarantined_seats.insert(record.seat.clone());
        summary.quarantined += 1;
    }
}
