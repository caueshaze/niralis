use niralis_protocol::{SessionInfo, SessionKind};
use std::path::PathBuf;

use crate::{
    SessionExecPlan, SessionRequest, StartedSession, WorkerEnvelope, WorkerRequest, WorkerResponse,
    WorkerSecret, WORKER_PROTOCOL_VERSION,
};

fn session(kind: SessionKind) -> SessionInfo {
    SessionInfo {
        id: if matches!(kind, SessionKind::Wayland) {
            "niri"
        } else {
            "plasma"
        }
        .to_owned(),
        name: if matches!(kind, SessionKind::Wayland) {
            "Niri"
        } else {
            "Plasma"
        }
        .to_owned(),
        kind,
    }
}

#[test]
fn worker_request_round_trip_preserves_wayland_x11_and_secret() {
    for kind in [SessionKind::Wayland, SessionKind::X11] {
        let encoded = serde_json::to_string(&WorkerEnvelope {
            version: WORKER_PROTOCOL_VERSION,
            message: WorkerRequest::PamSession {
                request: SessionRequest {
                    username: "test".to_owned(),
                    session: session(kind),
                },
                pam_service: "niralis".to_owned(),
                password: WorkerSecret::new("secret".to_owned()),
                session_child_path: PathBuf::from("/usr/libexec/niralis-session-child"),
                session_probe_path: PathBuf::from("/usr/libexec/niralis-session-probe"),
                control_path: PathBuf::from("/run/niralis/worker-control/control.sock"),
                worker_id: "worker-1".to_owned(),
                launcher_pid: 123,
                launch_plan: SessionExecPlan {
                    source_path: b"/usr/share/wayland-sessions/niri.desktop".to_vec(),
                    executable: b"/usr/bin/niri".to_vec(),
                    argv: vec![b"niri".to_vec(), b"--session".to_vec()],
                },
            },
        })
        .expect("request should serialize");
        let decoded: WorkerEnvelope<WorkerRequest> =
            serde_json::from_str(&encoded).expect("request should deserialize");

        assert_eq!(decoded.version, WORKER_PROTOCOL_VERSION);
        match decoded.message {
            WorkerRequest::PamSession {
                request,
                pam_service,
                password,
                session_child_path,
                session_probe_path,
                control_path,
                worker_id,
                launcher_pid,
                launch_plan,
            } => {
                assert_eq!(request.username, "test");
                assert_eq!(request.session, session(kind));
                assert_eq!(pam_service, "niralis");
                assert_eq!(password.expose(), "secret");
                assert_eq!(
                    session_child_path,
                    PathBuf::from("/usr/libexec/niralis-session-child")
                );
                assert_eq!(
                    session_probe_path,
                    PathBuf::from("/usr/libexec/niralis-session-probe")
                );
                assert_eq!(
                    control_path,
                    PathBuf::from("/run/niralis/worker-control/control.sock")
                );
                assert_eq!(worker_id, "worker-1");
                assert_eq!(launcher_pid, 123);
                assert_eq!(
                    launch_plan.argv,
                    vec![b"niri".to_vec(), b"--session".to_vec()]
                );
                assert_eq!(launch_plan.executable, b"/usr/bin/niri".to_vec());
                assert_eq!(
                    launch_plan.source_path,
                    b"/usr/share/wayland-sessions/niri.desktop".to_vec()
                );
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }
}

#[test]
fn worker_response_round_trip_preserves_session() {
    for kind in [SessionKind::Wayland, SessionKind::X11] {
        let encoded = serde_json::to_string(&WorkerEnvelope {
            version: WORKER_PROTOCOL_VERSION,
            message: WorkerResponse::Ready {
                session: StartedSession {
                    username: "test".to_owned(),
                    session: session(kind),
                },
            },
        })
        .expect("response should serialize");
        let decoded: WorkerEnvelope<WorkerResponse> =
            serde_json::from_str(&encoded).expect("response should deserialize");

        assert_eq!(
            decoded.message,
            WorkerResponse::Ready {
                session: StartedSession {
                    username: "test".to_owned(),
                    session: session(kind),
                },
            }
        );
    }
}

#[test]
fn worker_control_request_round_trip_is_bound_to_lifecycle() {
    let request = crate::WorkerControlRequest::Terminate {
        worker_id: "worker-opaque-1".to_owned(),
        expected_worker_pid: 100,
        expected_session_pid: 200,
        expected_session_pgid: 200,
    };
    let encoded = serde_json::to_string(&crate::WorkerEnvelope {
        version: crate::WORKER_CONTROL_PROTOCOL_VERSION,
        message: request.clone(),
    })
    .expect("control request should serialize");
    assert!(encoded.len() < crate::MAX_WORKER_CONTROL_MESSAGE_BYTES);
    let decoded: crate::WorkerEnvelope<crate::WorkerControlRequest> =
        serde_json::from_str(&encoded).expect("control request should deserialize");
    assert_eq!(decoded.version, crate::WORKER_CONTROL_PROTOCOL_VERSION);
    assert_eq!(decoded.message, request);
}

#[test]
fn payload_scope_release_messages_round_trip_with_identity_and_nonce() {
    let identity = crate::PayloadScopeIdentity {
        unit_name: "niralis-payload-release.scope".into(),
        invocation_id: "0123456789abcdef0123456789abcdef".into(),
        expected_uid: 1000,
        logind_session_id: crate::LogindSessionId::new("c1".into()).unwrap(),
    };
    let request = crate::WorkerControlRequest::PayloadScopeReleaseRequested {
        worker_id: "worker-opaque-1".into(),
        expected_worker_pid: 100,
        registration_nonce: "reg-1".into(),
        release_nonce: "release-1".into(),
        scope_identity: identity.clone(),
        local_cleanup_succeeded: true,
    };
    let encoded = serde_json::to_string(&crate::WorkerEnvelope {
        version: crate::WORKER_CONTROL_PROTOCOL_VERSION,
        message: request.clone(),
    })
    .unwrap();
    let decoded: crate::WorkerEnvelope<crate::WorkerControlRequest> =
        serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.message, request);
    let recovery = crate::WorkerControlRequest::PayloadScopeRecoveryRequired {
        worker_id: "worker-opaque-1".into(),
        expected_worker_pid: 100,
        registration_nonce: "reg-1".into(),
        release_nonce: "release-1".into(),
        reason: crate::PayloadScopeRecoveryReason::InvocationIdMismatch,
    };
    let encoded = serde_json::to_string(&crate::WorkerEnvelope {
        version: crate::WORKER_CONTROL_PROTOCOL_VERSION,
        message: recovery.clone(),
    })
    .unwrap();
    let decoded: crate::WorkerEnvelope<crate::WorkerControlRequest> =
        serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.message, recovery);
}

#[test]
fn terminal_vt_cleanup_messages_bind_identity_nonce_and_attempt() {
    let identity = crate::PayloadScopeIdentity {
        unit_name: "niralis-payload-terminal.scope".into(),
        invocation_id: "0123456789abcdef0123456789abcdef".into(),
        expected_uid: 1000,
        logind_session_id: crate::LogindSessionId::new("c1".into()).unwrap(),
    };
    let request = crate::WorkerControlRequest::TerminalVtCleanupResult {
        worker_id: "worker-terminal-1".into(),
        expected_worker_pid: 123,
        registration_nonce: "registration-nonce".into(),
        attempt_id: 9,
        result: crate::TerminalVtCleanupResult::VtDisallocateBusy,
    };
    let encoded = serde_json::to_string(&crate::WorkerEnvelope {
        version: crate::WORKER_CONTROL_PROTOCOL_VERSION,
        message: request.clone(),
    })
    .unwrap();
    let decoded: crate::WorkerEnvelope<crate::WorkerControlRequest> =
        serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.message, request);
    let intent = crate::WorkerControlRequest::TerminalVtCleanupIntent {
        worker_id: "worker-terminal-1".into(),
        expected_worker_pid: 123,
        registration_nonce: "registration-nonce".into(),
        scope_identity: identity,
    };
    assert!(serde_json::to_vec(&intent).unwrap().len() < crate::MAX_WORKER_CONTROL_MESSAGE_BYTES);
}

#[test]
fn worker_secret_debug_redacts_plaintext() {
    let secret = WorkerSecret::new("secret".to_owned());
    let debug = format!("{secret:?}");

    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("secret"));
}
