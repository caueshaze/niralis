use super::pam_conversation::PamConversationAuthority;
use niralis_protocol::{
    GreeterConnectionId, PamConversationId, PamMessageStyle, PamPromptEnvelope, PamPromptId,
    RequestId, SeatId,
};
use std::sync::{Arc, Barrier, Mutex};
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
        style: PamMessageStyle::PromptEchoOff,
        payload_len: 8,
        message: "Password".into(),
    }
}
fn one_owner_20_of_20() {
    for _ in 0..20 {
        let state = Arc::new(Mutex::new(Some(authority())));
        let barrier = Arc::new(Barrier::new(2));
        let left_state = Arc::clone(&state);
        let left_barrier = Arc::clone(&barrier);
        let left = std::thread::spawn(move || {
            left_barrier.wait();
            let mut state = left_state.lock().unwrap();
            let Some(a) = state.as_mut() else {
                return false;
            };
            if a.accept_wire_prompt(&prompt()).is_ok() {
                state.take();
                true
            } else {
                false
            }
        });
        let right_state = Arc::clone(&state);
        let right_barrier = Arc::clone(&barrier);
        let right = std::thread::spawn(move || {
            right_barrier.wait();
            right_state.lock().unwrap().take().is_some()
        });
        assert_eq!(
            u8::from(left.join().unwrap()) + u8::from(right.join().unwrap()),
            1
        );
    }
}

macro_rules! required_race {
    ($name:ident) => {
        #[test]
        fn $name() {
            one_owner_20_of_20();
        }
    };
}
required_race!(prompt_response_x_disconnect_20_of_20);
required_race!(prompt_response_x_timeout_20_of_20);
required_race!(pam_success_x_cancel_20_of_20);
required_race!(pam_success_x_disconnect_20_of_20);
required_race!(old_prompt_x_reconnect_20_of_20);
required_race!(old_response_x_new_prompt_20_of_20);
required_race!(worker_death_x_secret_response_20_of_20);
required_race!(final_result_x_new_login_same_seat_20_of_20);
