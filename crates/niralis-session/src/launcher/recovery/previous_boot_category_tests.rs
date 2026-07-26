use super::super::*;

#[test]
fn all_fact_and_policy_categories_remain_explicit() {
    assert_eq!(
        previous_boot_operation_policy(DurableOperationState::Confirmed { attempt_id: 1 }),
        PreviousBootOperationPolicy::HistoricalConfirmed
    );
    assert_eq!(
        previous_boot_operation_policy(DurableOperationState::Failed {
            attempt_id: 1,
            failure_class: 1
        }),
        PreviousBootOperationPolicy::HistoricalFailed
    );
    assert_eq!(
        previous_boot_operation_policy(DurableOperationState::NotStarted),
        PreviousBootOperationPolicy::EligibleForReadOnlyResolutionPlanning
    );
    let _ = PreviousBootOperationPolicy::CurrentBootInspectionRequired;
    let _ = CurrentIdentityObservation::Ambiguous;
    let _ = CurrentSeatRuntimeState::ClaimedByCurrentLifecycle;
    let _ = CurrentSeatRuntimeState::QuarantinedByCurrentRecord;
    let _ = CurrentSeatRuntimeState::Conflicting;
    let _ = CurrentVtDisposition::Foreground;
    let _ = CurrentVtDisposition::UsedByCurrentLifecycle;
    let _ = CurrentVtDisposition::VisibleCurrentHolder;
    let _ = CurrentVtDisposition::Ambiguous;
    let _ = PreviousBootRecoveryPlan::KeepQuarantined {
        reason: "historical",
    };
}
