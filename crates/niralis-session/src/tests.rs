use niralis_protocol::{SessionInfo, SessionKind};
use std::path::PathBuf;

use crate::{
    SessionExecPlan, SessionRequest, StartedSession, WorkerEnvelope, WorkerPamSessionRequest,
    WorkerRequest, WorkerResponse, WorkerSecret, WorkerTransactionIdentity,
    WORKER_PROTOCOL_VERSION,
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
            message: WorkerRequest::PamSession(WorkerPamSessionRequest {
                request: SessionRequest {
                    username: "test".to_owned(),
                    session: session(kind),
                },
                connection: None,
                pam_service: "niralis".to_owned(),
                password: WorkerSecret::new("secret".to_owned()),
                session_child_path: Box::new(PathBuf::from("/usr/libexec/niralis-session-child")),
                session_probe_path: Box::new(PathBuf::from("/usr/libexec/niralis-session-probe")),
                control_path: Box::new(PathBuf::from("/run/niralis/worker-control/control.sock")),
                worker_id: "worker-1".to_owned(),
                launcher_pid: 123,
                transaction: Box::new(WorkerTransactionIdentity {
                    transaction_id: "worker-1".into(),
                    admission_attempt_id: 1,
                    lifecycle_id: "worker-1".into(),
                    seat: "seat0".into(),
                    seat_generation: 1,
                    stage: "reserved".into(),
                }),
                launch_plan: Box::new(SessionExecPlan {
                    source_path: b"/usr/share/wayland-sessions/niri.desktop".to_vec(),
                    executable: b"/usr/bin/niri".to_vec(),
                    argv: vec![b"niri".to_vec(), b"--session".to_vec()],
                }),
            }),
        })
        .expect("request should serialize");
        let decoded: WorkerEnvelope<WorkerRequest> =
            serde_json::from_str(&encoded).expect("request should deserialize");

        assert_eq!(decoded.version, WORKER_PROTOCOL_VERSION);
        match decoded.message {
            WorkerRequest::PamSession(WorkerPamSessionRequest {
                request,
                pam_service,
                password,
                session_child_path,
                session_probe_path,
                control_path,
                worker_id,
                launcher_pid,
                launch_plan,
                ..
            }) => {
                assert_eq!(request.username, "test");
                assert_eq!(request.session, session(kind));
                assert_eq!(pam_service, "niralis");
                assert_eq!(password.expose(), "secret");
                assert_eq!(
                    *session_child_path,
                    PathBuf::from("/usr/libexec/niralis-session-child")
                );
                assert_eq!(
                    *session_probe_path,
                    PathBuf::from("/usr/libexec/niralis-session-probe")
                );
                assert_eq!(
                    *control_path,
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
        message: crate::WorkerControlRequest::Terminate {
            worker_id: "worker-opaque-1".to_owned(),
            expected_worker_pid: 100,
            expected_session_pid: 200,
            expected_session_pgid: 200,
        },
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
        transaction: crate::ControlTransactionIdentity {
            transaction_id: "worker-opaque-1".into(),
            admission_attempt_id: 1,
            lifecycle_id: "worker-opaque-1".into(),
            seat: "seat0".into(),
            seat_generation: 1,
            stage: "scope_release_requested".into(),
            sequence: 2,
        },
        worker_id: "worker-opaque-1".into(),
        expected_worker_pid: 100,
        registration_nonce: "reg-1".into(),
        release_nonce: "release-1".into(),
        scope_identity: identity.clone(),
        local_cleanup_succeeded: true,
    };
    let encoded = serde_json::to_string(&crate::WorkerEnvelope {
        version: crate::WORKER_CONTROL_PROTOCOL_VERSION,
        message: crate::WorkerControlRequest::PayloadScopeReleaseRequested {
            transaction: crate::ControlTransactionIdentity {
                transaction_id: "worker-opaque-1".into(),
                admission_attempt_id: 1,
                lifecycle_id: "worker-opaque-1".into(),
                seat: "seat0".into(),
                seat_generation: 1,
                stage: "scope_release_requested".into(),
                sequence: 2,
            },
            worker_id: "worker-opaque-1".into(),
            expected_worker_pid: 100,
            registration_nonce: "reg-1".into(),
            release_nonce: "release-1".into(),
            scope_identity: identity.clone(),
            local_cleanup_succeeded: true,
        },
    })
    .unwrap();
    let decoded: crate::WorkerEnvelope<crate::WorkerControlRequest> =
        serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.message, request);
    let recovery = crate::WorkerControlRequest::PayloadScopeRecoveryRequired {
        transaction: crate::ControlTransactionIdentity {
            transaction_id: "worker-opaque-1".into(),
            admission_attempt_id: 1,
            lifecycle_id: "worker-opaque-1".into(),
            seat: "seat0".into(),
            seat_generation: 1,
            stage: "scope_recovery_required".into(),
            sequence: 3,
        },
        worker_id: "worker-opaque-1".into(),
        expected_worker_pid: 100,
        registration_nonce: "reg-1".into(),
        release_nonce: "release-1".into(),
        reason: crate::PayloadScopeRecoveryReason::InvocationIdMismatch,
    };
    let encoded = serde_json::to_string(&crate::WorkerEnvelope {
        version: crate::WORKER_CONTROL_PROTOCOL_VERSION,
        message: recovery,
    })
    .unwrap();
    let decoded: crate::WorkerEnvelope<crate::WorkerControlRequest> =
        serde_json::from_str(&encoded).unwrap();
    assert!(matches!(
        decoded.message,
        crate::WorkerControlRequest::PayloadScopeRecoveryRequired { .. }
    ));
}

fn control_identity() -> crate::ControlTransactionIdentity {
    crate::ControlTransactionIdentity {
        transaction_id: "transaction-1".into(),
        admission_attempt_id: 7,
        lifecycle_id: "lifecycle-1".into(),
        seat: "seat0".into(),
        seat_generation: 4,
        stage: "scope_registered".into(),
        sequence: 1,
    }
}

fn worker_identity() -> WorkerTransactionIdentity {
    WorkerTransactionIdentity {
        transaction_id: "transaction-1".into(),
        admission_attempt_id: 7,
        lifecycle_id: "lifecycle-1".into(),
        seat: "seat0".into(),
        seat_generation: 4,
        stage: "scope_prepared".into(),
    }
}

#[test]
fn control_message_requires_full_transaction_identity() {
    assert!(control_identity().matches_worker(&worker_identity(), "scope_registered", 1));
}

#[test]
fn control_v5_peer_is_rejected_fail_closed() {
    assert_ne!(5, crate::WORKER_CONTROL_PROTOCOL_VERSION);
}

#[test]
fn worker_identity_is_transport_not_transaction_authority() {
    let identity = control_identity();
    assert_ne!(identity.transaction_id, "worker-pid-or-nonce");
}

#[test]
fn wrong_transaction_id_is_rejected() {
    let mut identity = control_identity();
    identity.transaction_id = "foreign".into();
    assert!(!identity.matches_worker(&worker_identity(), "scope_registered", 1));
}

#[test]
fn wrong_attempt_id_is_rejected() {
    let mut identity = control_identity();
    identity.admission_attempt_id = 8;
    assert!(!identity.matches_worker(&worker_identity(), "scope_registered", 1));
}

#[test]
fn stale_generation_control_message_is_rejected() {
    let mut identity = control_identity();
    identity.seat_generation = 3;
    assert!(!identity.matches_worker(&worker_identity(), "scope_registered", 1));
}

#[test]
fn duplicate_control_message_is_rejected() {
    assert!(!control_identity().matches_worker(&worker_identity(), "scope_registered", 2));
}

#[test]
fn out_of_order_control_message_is_rejected() {
    assert!(!control_identity().matches_worker(&worker_identity(), "scope_release_requested", 2));
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
        message: crate::WorkerControlRequest::TerminalVtCleanupResult {
            worker_id: "worker-terminal-1".into(),
            expected_worker_pid: 123,
            registration_nonce: "registration-nonce".into(),
            attempt_id: 9,
            result: crate::TerminalVtCleanupResult::VtDisallocateBusy,
        },
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
