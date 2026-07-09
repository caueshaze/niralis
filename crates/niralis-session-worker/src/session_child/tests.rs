use super::protocol::{
    SessionChildEnvelope, SessionChildErrorCode, SessionChildRequest, SessionChildResponse,
    SESSION_CHILD_PROTOCOL_VERSION,
};

#[test]
fn protocol_round_trip_preserves_probe_and_ready() {
    let request = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildRequest::Probe {
            canonical_username: "canonical-user".to_owned(),
            session_id: "niri".to_owned(),
        },
    };
    let encoded = serde_json::to_string(&request).expect("request should serialize");
    let decoded: SessionChildEnvelope<SessionChildRequest> =
        serde_json::from_str(&encoded).expect("request should deserialize");
    assert_eq!(decoded, request);

    let rejected = SessionChildResponse::Rejected {
        code: SessionChildErrorCode::UnsupportedVersion,
    };
    let encoded = serde_json::to_string(&rejected).expect("response should serialize");
    let decoded: SessionChildResponse =
        serde_json::from_str(&encoded).expect("response should deserialize");
    assert_eq!(decoded, rejected);
}
