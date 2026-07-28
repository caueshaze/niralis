use super::pam_conversation::PamConversationAuthority;
use niralis_protocol::{
    GreeterConnectionId, PamConversationId, PamMessageStyle, PamPromptEnvelope, PamPromptId,
    RequestId, SeatId,
};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

fn wire_prompt(sequence: u64, id: u64) -> PamPromptEnvelope {
    PamPromptEnvelope {
        protocol_version: niralis_protocol::GREETER_PROTOCOL_VERSION,
        message_type: "pam_prompt".into(),
        connection_id: GreeterConnectionId::new_for_wire("conn-1".into()),
        connection_epoch: 9,
        seat: SeatId::new_for_wire("seat0".into()),
        request_id: RequestId(11),
        transaction_id: "tx-1".into(),
        conversation_id: PamConversationId::new_for_wire("conv-1".into()),
        prompt_id: PamPromptId(id),
        sequence,
        style: PamMessageStyle::PromptEchoOn,
        payload_len: 4,
        message: "User".into(),
    }
}

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

#[test]
fn prompt_disconnect_race_has_one_owner_20_of_20() {
    for _ in 0..20 {
        let state = Arc::new(Mutex::new(Some(authority())));
        let barrier = Arc::new(Barrier::new(2));
        let prompt_state = Arc::clone(&state);
        let prompt_barrier = Arc::clone(&barrier);
        let prompt = std::thread::spawn(move || {
            prompt_barrier.wait();
            let mut state = prompt_state.lock().unwrap();
            let Some(authority) = state.as_mut() else {
                return false;
            };
            if authority.accept_wire_prompt(&wire_prompt(1, 1)).is_ok() {
                state.take();
                true
            } else {
                false
            }
        });
        let disconnect_state = Arc::clone(&state);
        let disconnect_barrier = Arc::clone(&barrier);
        let disconnect = std::thread::spawn(move || {
            disconnect_barrier.wait();
            disconnect_state.lock().unwrap().take().is_some()
        });
        assert_eq!(
            prompt.join().unwrap() as u8 + disconnect.join().unwrap() as u8,
            1
        );
    }
}
