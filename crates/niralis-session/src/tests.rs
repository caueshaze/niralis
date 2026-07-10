use niralis_protocol::{SessionInfo, SessionKind};
use std::path::PathBuf;

use crate::{
    SessionRequest, StartedSession, WorkerEnvelope, WorkerRequest, WorkerResponse, WorkerSecret,
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
            message: WorkerRequest::PamSession {
                request: SessionRequest {
                    username: "test".to_owned(),
                    session: session(kind),
                },
                pam_service: "niralis".to_owned(),
                password: WorkerSecret::new("secret".to_owned()),
                session_child_path: PathBuf::from("/usr/libexec/niralis-session-child"),
                session_probe_path: PathBuf::from("/usr/libexec/niralis-session-probe"),
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
fn worker_secret_debug_redacts_plaintext() {
    let secret = WorkerSecret::new("secret".to_owned());
    let debug = format!("{secret:?}");

    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("secret"));
}
