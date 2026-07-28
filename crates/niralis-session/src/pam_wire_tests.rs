use super::pam_conversation_tests::authority;
use niralis_protocol::{
    GreeterConnectionId, PamConversationId, PamMessageStyle, PamPromptEnvelope, PamPromptId,
    PamPromptResponse, PamPromptResponseEnvelope, RequestId, SeatId,
};

fn prompt() -> PamPromptEnvelope {
    PamPromptEnvelope {
        protocol_version: niralis_protocol::GREETER_PROTOCOL_VERSION,
        message_type: "pam_prompt".into(),
        connection_id: GreeterConnectionId::new_for_wire("conn-1".into()),
        connection_epoch: 9,
        seat: SeatId::new_for_wire("seat0".into()),
        request_id: RequestId(11),
        transaction_id: "tx-1".into(),
        conversation_id: PamConversationId::new_for_wire("conv-1".into()),
        prompt_id: PamPromptId(1),
        sequence: 1,
        style: PamMessageStyle::PromptEchoOn,
        payload_len: 4,
        message: "User".into(),
    }
}
fn response(connection: &str) -> PamPromptResponseEnvelope {
    PamPromptResponseEnvelope {
        protocol_version: niralis_protocol::GREETER_PROTOCOL_VERSION,
        message_type: "pam_prompt_response".into(),
        connection_id: GreeterConnectionId::new_for_wire(connection.into()),
        connection_epoch: 9,
        seat: SeatId::new_for_wire("seat0".into()),
        request_id: RequestId(11),
        transaction_id: "tx-1".into(),
        conversation_id: PamConversationId::new_for_wire("conv-1".into()),
        prompt_id: PamPromptId(1),
        sequence: 1,
        style: PamMessageStyle::PromptEchoOn,
        payload_len: 17,
        response: PamPromptResponse::Text("user".into()),
    }
}
#[test]
fn duplicate_prompt_is_rejected() {
    let mut a = authority();
    a.accept_wire_prompt(&prompt()).unwrap();
    assert!(a.accept_wire_prompt(&prompt()).is_err());
}
#[test]
fn foreign_connection_cannot_answer_prompt() {
    let mut a = authority();
    a.accept_wire_prompt(&prompt()).unwrap();
    assert!(a.accept_wire_response(&response("foreign")).is_err());
    assert!(a.accept_wire_response(&response("conn-1")).is_ok());
}
#[test]
fn response_after_consumption_is_rejected() {
    let mut a = authority();
    a.accept_wire_prompt(&prompt()).unwrap();
    let response = response("conn-1");
    a.accept_wire_response(&response).unwrap();
    assert!(a.accept_wire_response(&response).is_err());
}
