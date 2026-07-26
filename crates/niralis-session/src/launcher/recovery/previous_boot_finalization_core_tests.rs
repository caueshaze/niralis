use super::super::attempts::next_operation_attempt_id;
use super::*;

#[test]
fn finalization_attempts_follow_historical_attempts() {
    let mut value = super::super::finalization_fixture::record("pending");
    value.operation_ledger.payload_kill = DurableOperationState::IntentPersisted { attempt_id: 1 };
    value.operation_ledger.supervisor_unref = DurableOperationState::Indeterminate {
        attempt_id: 2,
        stage: 1,
    };
    value.operation_ledger.logind_termination =
        DurableOperationState::IntentPersisted { attempt_id: 3 };
    value.operation_ledger.vt_disallocate = DurableOperationState::Indeterminate {
        attempt_id: 4,
        stage: 1,
    };
    assert_eq!(next_operation_attempt_id(&value).unwrap(), 5);
    value.sequence = 3;
    value.state = "record_resolved".to_owned();
    value.operation_ledger.record_resolution = DurableOperationState::Confirmed { attempt_id: 5 };
    assert!(validate_historical_record(&value).is_empty());
    assert_eq!(next_operation_attempt_id(&value).unwrap(), 6);
}
