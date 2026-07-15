use super::protocol::{
    SessionChildCommit, SessionChildEnvelope, SessionChildErrorCode, SessionChildRequest,
    SessionChildResponse, SessionChildRuntimeContext, SessionChildUnixCredentials,
    SessionChildUnixPath, SessionProbeHandoff, SessionProcessIdentityProof,
    SessionRuntimeEnvironmentProof, SESSION_CHILD_PROTOCOL_VERSION, SESSION_EXEC_PROBE_VERSION,
};
use crate::isolation::{CapabilityState, PostDropIsolationProof};
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

fn proof() -> super::protocol::SessionChildIsolationProof {
    super::protocol::SessionChildIsolationProof::from(&PostDropIsolationProof {
        capabilities: CapabilityState {
            effective: vec![],
            permitted: vec![],
            inheritable: vec![],
            ambient: vec![],
            bounding: vec![0],
            cap_last_cap: 0,
        },
        securebits: 0,
        no_new_privs: false,
        open_fds: vec![0, 1, 2],
    })
}
fn runtime() -> SessionChildRuntimeContext {
    SessionChildRuntimeContext {
        home: SessionChildUnixPath {
            bytes: b"/home/test".to_vec(),
        },
        shell: SessionChildUnixPath {
            bytes: b"/bin/bash".to_vec(),
        },
        session_type: "wayland".into(),
        session_class: "user".into(),
        session_desktop: "niri".into(),
        session_id: "niri".into(),
        runtime_dir: SessionChildUnixPath {
            bytes: b"/run/user/1000".to_vec(),
        },
        seat: "seat0".into(),
        vtnr: 1,
        dbus_session_bus_address: None,
        imported_locale: Vec::new(),
        selinux_exec_context: None,
        probe_path: SessionChildUnixPath {
            bytes: b"/probe".to_vec(),
        },
        exec_plan: niralis_session::SessionExecPlan {
            source_path: b"/source.desktop".to_vec(),
            executable: b"/bin/true".to_vec(),
            argv: vec![b"true".to_vec()],
        },
    }
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
            runtime: runtime(),
            terminal: None,
        },
    };
    let mut bytes = serde_json::to_vec(&envelope).expect("request should serialize");
    bytes.push(b'\n');
    bytes
}

#[test]
fn protocol_round_trip_preserves_probe_and_ready() {
    assert_eq!(SESSION_CHILD_PROTOCOL_VERSION, 9);
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
            runtime: runtime(),
            terminal: None,
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
fn sealed_probe_handoff_round_trips_without_changing_child_protocol_version() {
    let handoff = SessionProbeHandoff {
        exec_plan: runtime().exec_plan,
        selinux_exec_context: None,
    };
    let encoded = serde_json::to_vec(&handoff).expect("handoff should serialize");
    let decoded: SessionProbeHandoff =
        serde_json::from_slice(&encoded).expect("handoff should deserialize");
    assert_eq!(decoded, handoff);
    assert_eq!(SESSION_CHILD_PROTOCOL_VERSION, 9);
    assert_eq!(SESSION_EXEC_PROBE_VERSION, 2);
}

#[test]
fn child_rejects_the_previous_private_protocol_version() {
    let mut payload = request(1000);
    let mut request: SessionChildEnvelope<SessionChildRequest> =
        serde_json::from_slice(&payload[..payload.len() - 1]).expect("request should parse");
    request.version = 8;
    payload = serde_json::to_vec(&request).expect("request should serialize");
    payload.push(b'\n');
    let mut output = Vec::new();
    let dropper = StubDropper {
        result: Ok(AppliedCredentials {
            uid: 1000,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        }),
        calls: AtomicUsize::new(0),
        target: Mutex::new(None),
    };
    assert_ne!(
        super::run_child_process_with_dropper(Cursor::new(payload), &mut output, &dropper, 42),
        0
    );
    assert_eq!(dropper.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn commit_exec_is_bounded_and_round_trips() {
    let envelope = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildCommit::Exec,
    };
    let bytes = serde_json::to_vec(&envelope).expect("commit should serialize");
    let decoded: SessionChildEnvelope<SessionChildCommit> =
        serde_json::from_slice(&bytes).expect("commit should deserialize");
    assert_eq!(decoded, envelope);
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
            runtime: runtime(),
            terminal: None,
        },
    };
    let payload = serde_json::to_vec(&envelope).expect("maximum request should serialize");
    assert!(payload.len() + 1 <= super::protocol::MAX_SESSION_CHILD_MESSAGE_BYTES);
}

#[test]
fn ready_binding_rejects_each_identity_or_credential_mismatch() {
    let expectation = super::SessionChildExpectation {
        canonical_username: "canonical-user".to_owned(),
        session_id: "niri".to_owned(),
        target_credentials: PrivilegeDropTarget {
            uid: 1000,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        },
        runtime: runtime(),
        terminal: None,
    };
    let expected = SessionChildUnixCredentials {
        uid: 1000,
        gid: 1000,
        supplementary_gids: vec![10, 20],
    };

    let cases = [
        ("username", "wrong-user".to_owned(), expected.clone()),
        ("session", "wrong-session".to_owned(), expected.clone()),
        (
            "pid",
            "canonical-user".to_owned(),
            SessionChildUnixCredentials {
                uid: expected.uid,
                gid: expected.gid,
                supplementary_gids: expected.supplementary_gids.clone(),
            },
        ),
        (
            "uid",
            "canonical-user".to_owned(),
            SessionChildUnixCredentials {
                uid: 999,
                ..expected.clone()
            },
        ),
        (
            "gid",
            "canonical-user".to_owned(),
            SessionChildUnixCredentials {
                gid: 999,
                ..expected.clone()
            },
        ),
        (
            "supplementary-gids",
            "canonical-user".to_owned(),
            SessionChildUnixCredentials {
                supplementary_gids: vec![10, 30],
                ..expected.clone()
            },
        ),
    ];

    for (field, username, applied_credentials) in cases {
        let session_id = if field == "session" {
            "wrong-session".to_owned()
        } else {
            "niri".to_owned()
        };
        let child_pid = if field == "pid" { 43 } else { 42 };
        let response = SessionChildResponse::Ready {
            canonical_username: username,
            session_id,
            child_pid,
            applied_credentials,
            credential_proof: super::protocol::SessionChildCredentialProof {
                real_uid: 1000,
                effective_uid: 1000,
                saved_uid: 1000,
                real_gid: 1000,
                effective_gid: 1000,
                saved_gid: 1000,
                supplementary_gids: vec![10, 20],
            },
            isolation_proof: proof(),
            process_identity: SessionProcessIdentityProof {
                pid: child_pid,
                sid: 42,
                pgid: 42,
            },
            runtime_environment: SessionRuntimeEnvironmentProof {
                home: runtime().home.clone(),
                user: "canonical-user".into(),
                logname: "canonical-user".into(),
                shell: runtime().shell.clone(),
                path: super::DEFAULT_SESSION_PATH.into(),
                session_type: "wayland".into(),
                session_class: "user".into(),
                session_desktop: "niri".into(),
                session_id: "niri".into(),
                runtime_dir: runtime().runtime_dir.clone(),
                seat: "seat0".into(),
                vtnr: 1,
                dbus_session_bus_address: None,
                imported_locale: Vec::new(),
                forbidden_variables_present: Vec::new(),
                user_bus_connected: true,
                cwd: runtime().home,
                exec_plan: runtime().exec_plan,
            },
            exec_probe_version: SESSION_EXEC_PROBE_VERSION,
            terminal_proof: None,
        };

        assert_eq!(
            super::validate_ready_response(response, &expectation, 42, false),
            Err(super::SessionChildError::ProtocolFailed),
            "mismatch in {field} must be rejected"
        );
    }
}
