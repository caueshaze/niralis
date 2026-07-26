use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RecoveryRecordSetClassification {
    pub(crate) blocked_seats: BTreeSet<String>,
    pub(crate) same_boot_seats: BTreeSet<String>,
    pub(crate) previous_boot_seats: BTreeSet<String>,
    pub(crate) conflicts: Vec<RecordConflictReason>,
    pub(crate) global_quarantine: bool,
}

impl RecoveryRecordSetClassification {
    pub(crate) fn seat_blocked(&self, seat: &str) -> bool {
        self.blocked_seats.contains(seat)
    }
}

pub(crate) fn classify_recovery_record_set(
    results: &[DurableRecoveryRecordReadResult],
    current_boot: &BootIdentity,
) -> RecoveryRecordSetClassification {
    let mut out = RecoveryRecordSetClassification::default();
    let mut by_seat: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut lifecycles = BTreeSet::new();
    for result in results {
        let _ = (result.path(), result.known_seat());
        match result {
            DurableRecoveryRecordReadResult::ValidSameBoot { record, .. } => {
                out.same_boot_seats.insert(record.seat.clone());
                by_seat.entry(record.seat.clone()).or_default().0 += 1;
                if !lifecycles.insert(record.lifecycle_id.clone()) {
                    out.conflicts.push(RecordConflictReason::DuplicateLifecycle);
                    out.blocked_seats.insert(record.seat.clone());
                }
            }
            DurableRecoveryRecordReadResult::ValidPreviousBoot { record, .. } => {
                if record.created_boot_id == current_boot.as_str() {
                    out.same_boot_seats.insert(record.seat.clone());
                } else {
                    out.previous_boot_seats.insert(record.seat.clone());
                }
                by_seat.entry(record.seat.clone()).or_default().1 += 1;
                if !lifecycles.insert(record.lifecycle_id.clone()) {
                    out.conflicts.push(RecordConflictReason::DuplicateLifecycle);
                    out.blocked_seats.insert(record.seat.clone());
                }
            }
            DurableRecoveryRecordReadResult::Corrupted { .. }
            | DurableRecoveryRecordReadResult::UnsupportedVersion { .. }
            | DurableRecoveryRecordReadResult::UnsafeMetadata { .. }
            | DurableRecoveryRecordReadResult::HistoricalInvariantViolation { .. } => {
                out.global_quarantine = true;
            }
            DurableRecoveryRecordReadResult::IdentityMismatch { reason, .. } => {
                out.global_quarantine = true;
                out.conflicts.push(match reason {
                    RecordIdentityMismatch::DuplicateLifecycle => {
                        RecordConflictReason::DuplicateLifecycle
                    }
                    _ => RecordConflictReason::DuplicateRecordId,
                });
            }
            DurableRecoveryRecordReadResult::ConflictingRecords { reason, .. } => {
                if !matches!(
                    reason,
                    RecordConflictReason::SameSeatSameBootPrecedence
                        | RecordConflictReason::DuplicateLifecycle
                ) {
                    out.global_quarantine = true;
                }
                out.conflicts.push(reason.clone());
            }
        }
    }
    for (seat, (same, previous)) in by_seat {
        if same > 0 && previous > 0 {
            out.blocked_seats.insert(seat);
            out.conflicts
                .push(RecordConflictReason::SameSeatSameBootPrecedence);
        } else if previous > 1 || same > 1 {
            out.blocked_seats.insert(seat);
            out.conflicts.push(RecordConflictReason::DuplicateLifecycle);
        }
    }
    out.conflicts.sort_by_key(|value| format!("{value:?}"));
    out.conflicts.dedup();
    out
}
