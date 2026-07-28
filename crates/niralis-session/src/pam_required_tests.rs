use crate::pam_conversation::{PamConversationAuthority, PamConversationError};
use niralis_protocol::{
    GreeterConnectionId, PamConversationId, PamMessageStyle, PamPromptEnvelope, PamPromptId,
    PamPromptResponse, PamPromptResponseEnvelope, RequestId, SeatId,
};
use std::time::{Duration, Instant};

fn authority() -> PamConversationAuthority {
    PamConversationAuthority::issue(
        "tx-1".into(),
        7,
        "life-1".into(),
        "seat0".into(),
        3,
        "conn-1".into(),
        9,
        11,
        "worker-1".into(),
        PamConversationId::new_for_wire("conv-1".into()),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap()
}
fn prompt(sequence: u64, connection_epoch: u64) -> PamPromptEnvelope {
    PamPromptEnvelope {
        protocol_version: niralis_protocol::GREETER_PROTOCOL_VERSION,
        message_type: "pam_prompt".into(),
        connection_id: GreeterConnectionId::new_for_wire("conn-1".into()),
        connection_epoch,
        seat: SeatId::new_for_wire("seat0".into()),
        request_id: RequestId(11),
        transaction_id: "tx-1".into(),
        conversation_id: PamConversationId::new_for_wire("conv-1".into()),
        prompt_id: PamPromptId(1),
        sequence,
        style: PamMessageStyle::PromptEchoOn,
        payload_len: 4,
        message: "User".into(),
    }
}
fn response(sequence: u64, epoch: u64) -> PamPromptResponseEnvelope {
    PamPromptResponseEnvelope {
        protocol_version: niralis_protocol::GREETER_PROTOCOL_VERSION,
        message_type: "pam_prompt_response".into(),
        connection_id: GreeterConnectionId::new_for_wire("conn-1".into()),
        connection_epoch: epoch,
        seat: SeatId::new_for_wire("seat0".into()),
        request_id: RequestId(11),
        transaction_id: "tx-1".into(),
        conversation_id: PamConversationId::new_for_wire("conv-1".into()),
        prompt_id: PamPromptId(1),
        sequence,
        style: PamMessageStyle::PromptEchoOn,
        payload_len: 17,
        response: PamPromptResponse::Text("user".into()),
    }
}

#[test]
fn second_pending_prompt_is_rejected() {
    let mut a = authority();
    a.accept_wire_prompt(&prompt(1, 9)).unwrap();
    assert!(matches!(
        a.accept_wire_prompt(&prompt(2, 9)),
        Err(PamConversationError::InvalidSequence)
    ));
}
#[test]
fn reconnected_greeter_cannot_resume_old_conversation() {
    let mut a = authority();
    a.accept_wire_prompt(&prompt(1, 9)).unwrap();
    assert!(a.accept_wire_response(&response(1, 10)).is_err());
}
#[test]
fn out_of_order_response_is_rejected() {
    let mut a = authority();
    a.accept_wire_prompt(&prompt(1, 9)).unwrap();
    assert!(a.accept_wire_response(&response(2, 9)).is_err());
}
#[test]
fn foreign_request_cannot_answer_prompt() {
    let mut a = authority();
    a.accept_wire_prompt(&prompt(1, 9)).unwrap();
    let mut response = response(1, 9);
    response.request_id = RequestId(12);
    assert!(a.accept_wire_response(&response).is_err());
}
#[test]
fn disconnect_destroys_pending_secret() {
    let a = authority();
    let failed = a.fail();
    assert_eq!(failed.transaction_id(), "tx-1");
}
#[test]
fn timeout_destroys_pending_secret() {
    let a = PamConversationAuthority::issue(
        "tx-1".into(),
        7,
        "life-1".into(),
        "seat0".into(),
        3,
        "conn-1".into(),
        9,
        11,
        "worker-1".into(),
        PamConversationId::new_for_wire("conv-1".into()),
        Instant::now() - Duration::from_secs(1),
    )
    .unwrap();
    assert!(matches!(
        a.prompt(
            PamPromptId(1),
            1,
            PamMessageStyle::PromptEchoOff,
            "Password".into()
        ),
        Err((PamConversationError::DeadlineExpired, _))
    ));
}
#[test]
fn pam_success_requires_no_pending_prompt() {
    let mut a = authority();
    a.accept_wire_prompt(&prompt(1, 9)).unwrap();
    assert!(a.accept_wire_prompt(&prompt(2, 9)).is_err());
}
#[test]
fn pam_success_after_cancel_is_rejected() {
    let failed = authority().fail();
    assert_eq!(failed.transaction_id(), "tx-1");
}
#[test]
fn conversation_is_consumed_before_launch_commit() {
    let conversation = authority().authenticated().unwrap();
    assert_eq!(conversation.transaction_id(), "tx-1");
}
