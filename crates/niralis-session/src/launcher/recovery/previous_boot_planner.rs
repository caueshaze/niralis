use super::super::*;
use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PreviousBootRecoveryPlan {
    ResolveHistoricalRecord,
    FinalizeAlreadyResolvedRecord,
    KeepQuarantined {
        reason: &'static str,
    },
    QuarantineSeatConflict {
        seat: String,
        conflict: &'static str,
    },
    QuarantineGlobally {
        reason: &'static str,
    },
    InspectionRequired {
        missing: Vec<&'static str>,
    },
    RejectMalformedHistory {
        violations: Vec<&'static str>,
    },
}

pub(crate) fn plan_previous_boot_reconciliation(
    record: &PreviousBootRecoveryRecord,
    facts: &PreviousBootCurrentFacts,
) -> PreviousBootRecoveryPlan {
    previous_boot_taxonomy_is_complete();
    let violations = historical_invariant_violations(&record.record);
    if !violations.is_empty() {
        return PreviousBootRecoveryPlan::RejectMalformedHistory { violations };
    }
    if facts.ambiguous_neighbor {
        return PreviousBootRecoveryPlan::QuarantineGlobally {
            reason: "ambiguous recovery ledger neighbor",
        };
    }
    if !facts.authority.stable {
        return PreviousBootRecoveryPlan::InspectionRequired {
            missing: vec!["stable systemd/logind authority snapshot"],
        };
    }
    if !facts.inspection_failures.is_empty() {
        return PreviousBootRecoveryPlan::InspectionRequired {
            missing: vec!["complete current-boot inspection"],
        };
    }
    if !facts.historical_pid_reuse.is_empty() {
        return PreviousBootRecoveryPlan::QuarantineSeatConflict {
            seat: record.record.seat.clone(),
            conflict: "current PID is a new identity",
        };
    }
    if !facts.competing_records.is_empty() {
        return PreviousBootRecoveryPlan::QuarantineSeatConflict {
            seat: record.record.seat.clone(),
            conflict: "competing recovery record",
        };
    }
    if facts.has_same_boot_record_for_seat {
        return PreviousBootRecoveryPlan::QuarantineSeatConflict {
            seat: record.record.seat.clone(),
            conflict: "same-boot record takes precedence",
        };
    }
    if facts.has_newer_record_for_seat {
        return PreviousBootRecoveryPlan::QuarantineSeatConflict {
            seat: record.record.seat.clone(),
            conflict: "newer record exists for seat",
        };
    }
    let observations = [
        &facts.conflicts.same_unit_name,
        &facts.conflicts.same_invocation_id,
        &facts.conflicts.same_cgroup_path,
        &facts.conflicts.same_session_id,
        &facts.conflicts.same_lifecycle_id,
    ];
    if observations.iter().any(|value| {
        matches!(
            value,
            CurrentIdentityObservation::PresentButDifferentIdentity
                | CurrentIdentityObservation::PresentAndConflicting
                | CurrentIdentityObservation::Ambiguous
        )
    }) {
        return PreviousBootRecoveryPlan::QuarantineSeatConflict {
            seat: record.record.seat.clone(),
            conflict: "current boot identity conflict",
        };
    }
    let mut missing = Vec::new();
    if observations
        .iter()
        .any(|value| matches!(value, CurrentIdentityObservation::InspectionUnavailable))
    {
        missing.push("current identity inspection");
    }
    if !facts.seat.inspection_complete
        || matches!(facts.seat.runtime_state, CurrentSeatRuntimeState::Unknown)
    {
        missing.push("current seat inspection");
    }
    if record.record.target_vt.is_some()
        && facts.vt.as_ref().is_none_or(|value| {
            !value.inspection_complete
                || matches!(
                    value.disposition,
                    CurrentVtDisposition::InspectionUnavailable | CurrentVtDisposition::Ambiguous
                )
                || !value.visible_holders.is_empty()
        })
    {
        missing.push("current VT inspection");
    }
    if !missing.is_empty() {
        return PreviousBootRecoveryPlan::InspectionRequired { missing };
    }
    if !matches!(facts.seat.runtime_state, CurrentSeatRuntimeState::Unclaimed) {
        return PreviousBootRecoveryPlan::QuarantineSeatConflict {
            seat: record.record.seat.clone(),
            conflict: "seat is occupied or quarantined",
        };
    }
    if facts.vt.as_ref().is_some_and(|value| {
        !matches!(
            value.disposition,
            CurrentVtDisposition::NotForegroundAndUnused
        )
    }) {
        return PreviousBootRecoveryPlan::QuarantineSeatConflict {
            seat: record.record.seat.clone(),
            conflict: "VT is current-boot resource",
        };
    }
    if record.record.state == "quarantined" {
        PreviousBootRecoveryPlan::KeepQuarantined {
            reason: "historical quarantine requires later execution phase",
        }
    } else if record.record.state == "record_resolved" {
        PreviousBootRecoveryPlan::FinalizeAlreadyResolvedRecord
    } else {
        PreviousBootRecoveryPlan::ResolveHistoricalRecord
    }
}

// Keep the exhaustive state vocabulary linked into non-test builds. This is
// intentionally separate from planning: every state has a typed meaning even
// when the conservative Linux inspector cannot currently observe it.
fn previous_boot_taxonomy_is_complete() {
    let _ = [
        CurrentIdentityObservation::Absent,
        CurrentIdentityObservation::PresentButDifferentIdentity,
        CurrentIdentityObservation::PresentAndConflicting,
        CurrentIdentityObservation::Ambiguous,
        CurrentIdentityObservation::InspectionUnavailable,
    ];
    let _ = [
        CurrentSeatRuntimeState::Unclaimed,
        CurrentSeatRuntimeState::ClaimedByCurrentLifecycle,
        CurrentSeatRuntimeState::QuarantinedByCurrentRecord,
        CurrentSeatRuntimeState::Conflicting,
        CurrentSeatRuntimeState::Unknown,
    ];
    let _ = [
        CurrentVtDisposition::NotForegroundAndUnused,
        CurrentVtDisposition::Foreground,
        CurrentVtDisposition::UsedByCurrentLifecycle,
        CurrentVtDisposition::VisibleCurrentHolder,
        CurrentVtDisposition::Ambiguous,
        CurrentVtDisposition::InspectionUnavailable,
    ];
    let _ = [
        PreviousBootOperationPolicy::HistoricalConfirmed,
        PreviousBootOperationPolicy::HistoricalFailed,
        PreviousBootOperationPolicy::HistoricalIndeterminateNeverReplay,
        PreviousBootOperationPolicy::CurrentBootInspectionRequired,
        PreviousBootOperationPolicy::EligibleForReadOnlyResolutionPlanning,
    ];
}

fn historical_invariant_violations(record: &PersistentRecoveryRecord) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if record.sequence == 0 {
        violations.push("sequence regression");
    }
    if record.state == "record_resolved"
        && !matches!(
            record.operation_ledger.record_resolution,
            DurableOperationState::Confirmed { .. } | DurableOperationState::NotStarted
        )
    {
        violations.push("record resolved has nonterminal resolution operation");
    }
    if matches!(
        record.operation_ledger.runtime_release,
        DurableOperationState::Confirmed { .. }
    ) && record.state != "record_resolved"
    {
        violations.push("runtime release confirmed before record resolved");
    }
    violations
}
