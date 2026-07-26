use super::*;
pub(super) fn previous_boot_current_facts(
    host: &dyn PreviousBootInspectionHost,
    record: &PreviousBootRecoveryRecord,
    records: &[PersistentRecoveryRecord],
    ambiguous_neighbor: bool,
) -> PreviousBootCurrentFacts {
    let request = PreviousBootInspectionRequest {
        record: record.clone(),
        records: records.to_vec(),
    };
    let mut facts = match host.inspect_current_snapshot(&request) {
        Ok(facts) => facts,
        Err(error) => PreviousBootCurrentFacts {
            conflicts: CurrentBootConflictFacts {
                same_unit_name: CurrentIdentityObservation::InspectionUnavailable,
                same_invocation_id: CurrentIdentityObservation::InspectionUnavailable,
                same_cgroup_path: CurrentIdentityObservation::InspectionUnavailable,
                same_session_id: CurrentIdentityObservation::InspectionUnavailable,
                same_lifecycle_id: CurrentIdentityObservation::InspectionUnavailable,
            },
            inspection_failures: vec![error],
            ..PreviousBootCurrentFacts::default()
        },
    };
    facts.ambiguous_neighbor = ambiguous_neighbor;
    facts
}

pub(super) fn log_previous_boot_plan(
    record: &PreviousBootRecoveryRecord,
    plan: &PreviousBootRecoveryPlan,
) {
    let policies = [
        record.record.operation_ledger.payload_kill,
        record.record.operation_ledger.supervisor_unref,
        record.record.operation_ledger.logind_termination,
        record.record.operation_ledger.vt_disallocate,
        record.record.operation_ledger.runtime_release,
        record.record.operation_ledger.record_resolution,
    ]
    .map(previous_boot_operation_policy);
    match plan {
        PreviousBootRecoveryPlan::ResolveHistoricalRecord
        | PreviousBootRecoveryPlan::FinalizeAlreadyResolvedRecord => {
            info!(lifecycle_id = %record.record.lifecycle_id, recorded_boot = %record.recorded_boot.as_str(), ?policies, "previous_boot_resolution_planned; historical operations are not replayed")
        }
        PreviousBootRecoveryPlan::RejectMalformedHistory { .. } => {
            warn!(lifecycle_id = %record.record.lifecycle_id, recorded_boot = %record.recorded_boot.as_str(), ?policies, ?plan, "malformed_history")
        }
        PreviousBootRecoveryPlan::InspectionRequired { .. }
        | PreviousBootRecoveryPlan::KeepQuarantined { .. }
        | PreviousBootRecoveryPlan::QuarantineSeatConflict { .. }
        | PreviousBootRecoveryPlan::QuarantineGlobally { .. } => {
            warn!(lifecycle_id = %record.record.lifecycle_id, recorded_boot = %record.recorded_boot.as_str(), ?policies, ?plan, "previous_boot_quarantine_planned")
        }
    }
}
