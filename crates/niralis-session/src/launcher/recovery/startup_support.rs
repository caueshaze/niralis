use super::*;
pub(super) fn persisted_decision(record: &PersistentRecoveryRecord) -> StartupRecoveryDecision {
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

pub(super) fn startup_failure_catalog() -> [StartupRecoveryFailure; 11] {
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

pub(super) fn conflicts(records: &[PersistentRecoveryRecord]) -> BTreeSet<String> {
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
