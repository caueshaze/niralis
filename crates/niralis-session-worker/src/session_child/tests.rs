use super::protocol::{
    SessionChildEnvelope, SessionChildErrorCode, SessionChildRequest, SessionChildResponse,
    SESSION_CHILD_PROTOCOL_VERSION,
};
use crate::privilege_drop::{
    AppliedCredentials, PrivilegeDropError, PrivilegeDropTarget, PrivilegeDropper,
};
use std::io::Cursor;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

struct StubDropper {
    result: Result<AppliedCredentials, PrivilegeDropError>,
    calls: AtomicUsize,
    target: Mutex<Option<PrivilegeDropTarget>>,
}

impl PrivilegeDropper for StubDropper {
    fn drop_privileges(
        &self,
        target: &PrivilegeDropTarget,
    ) -> Result<AppliedCredentials, PrivilegeDropError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.target.lock().unwrap() = Some(target.clone());
        self.result.clone()
    }
}

fn request(uid: u32) -> Vec<u8> {
    let envelope = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildRequest::ApplyCredentials {
            canonical_username: "canonical-user".to_owned(),
            session_id: "niri".to_owned(),
            credentials: super::protocol::SessionChildUnixCredentials {
                uid,
                gid: 1000,
                supplementary_gids: vec![10, 20],
            },
        },
    };
    let mut bytes = serde_json::to_vec(&envelope).expect("request should serialize");
    bytes.push(b'\n');
    bytes
}

#[test]
fn protocol_round_trip_preserves_probe_and_ready() {
    let request = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildRequest::ApplyCredentials {
            canonical_username: "canonical-user".to_owned(),
            session_id: "niri".to_owned(),
            credentials: super::protocol::SessionChildUnixCredentials {
                uid: 1000,
                gid: 1000,
                supplementary_gids: vec![10, 20],
            },
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

#[test]
fn child_core_writes_ready_from_observed_applied_credentials() {
    let dropper = StubDropper {
        result: Ok(AppliedCredentials {
            uid: 1000,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        }),
        calls: AtomicUsize::new(0),
        target: Mutex::new(None),
    };
    let mut output = Vec::new();
    let code = super::run_child_process_with_dropper(
        Cursor::new(request(1000)),
        &mut output,
        &dropper,
        42,
    );
    assert_eq!(code, 0);
    assert_eq!(dropper.calls.load(Ordering::SeqCst), 1);
    assert_eq!(dropper.target.lock().unwrap().as_ref().unwrap().uid, 1000);
    let response: SessionChildEnvelope<SessionChildResponse> =
        serde_json::from_slice(&output[..output.len() - 1]).expect("response should parse");
    match response.message {
        SessionChildResponse::Ready {
            applied_credentials,
            ..
        } => {
            assert_eq!(applied_credentials.uid, 1000);
            assert_eq!(applied_credentials.supplementary_gids, vec![10, 20]);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn child_core_rejects_root_without_calling_dropper() {
    let dropper = StubDropper {
        result: Ok(AppliedCredentials {
            uid: 0,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        }),
        calls: AtomicUsize::new(0),
        target: Mutex::new(None),
    };
    let mut output = Vec::new();
    let code =
        super::run_child_process_with_dropper(Cursor::new(request(0)), &mut output, &dropper, 42);
    assert_ne!(code, 0);
    assert_eq!(dropper.calls.load(Ordering::SeqCst), 0);
    assert!(!output.is_empty());
}

#[test]
fn child_core_rejects_dropper_failure_and_mismatch() {
    for result in [
        Err(PrivilegeDropError::SetUidFailed),
        Ok(AppliedCredentials {
            uid: 999,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        }),
    ] {
        let dropper = StubDropper {
            result,
            calls: AtomicUsize::new(0),
            target: Mutex::new(None),
        };
        let mut output = Vec::new();
        let code = super::run_child_process_with_dropper(
            Cursor::new(request(1000)),
            &mut output,
            &dropper,
            42,
        );
        assert_ne!(code, 0);
        assert_eq!(dropper.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn maximum_supported_credentials_fit_the_child_protocol() {
    let start = u32::MAX - 65_535;
    let credentials = super::protocol::SessionChildUnixCredentials {
        uid: 1000,
        gid: 0,
        supplementary_gids: (start..=u32::MAX).collect(),
    };
    let envelope = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildRequest::ApplyCredentials {
            canonical_username: "canonical-user".to_owned(),
            session_id: "niri".to_owned(),
            credentials,
        },
    };
    let payload = serde_json::to_vec(&envelope).expect("maximum request should serialize");
    assert!(payload.len() + 1 <= super::protocol::MAX_SESSION_CHILD_MESSAGE_BYTES);
}
