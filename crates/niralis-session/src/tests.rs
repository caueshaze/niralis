use std::io::Cursor;

use niralis_protocol::{SessionInfo, SessionKind};

use crate::{
    run_worker_process, SessionRequest, StartedSession, WorkerEnvelope, WorkerErrorCode,
    WorkerRequest, WorkerResponse, WORKER_PROTOCOL_VERSION,
};

fn session(kind: SessionKind) -> SessionInfo {
    SessionInfo {
        id: match kind {
            SessionKind::Wayland => "niri",
            SessionKind::X11 => "plasma",
        }
        .to_owned(),
        name: match kind {
            SessionKind::Wayland => "Niri",
            SessionKind::X11 => "Plasma",
        }
        .to_owned(),
        kind,
    }
}

#[test]
fn worker_request_round_trip_preserves_wayland_and_x11() {
    for kind in [SessionKind::Wayland, SessionKind::X11] {
        let encoded = serde_json::to_string(&WorkerEnvelope {
            version: WORKER_PROTOCOL_VERSION,
            message: WorkerRequest::PrepareSession {
                request: SessionRequest {
                    username: "test".to_owned(),
                    session: session(kind),
                },
            },
        })
        .expect("request should serialize");

        let decoded: WorkerEnvelope<WorkerRequest> =
            serde_json::from_str(&encoded).expect("request should deserialize");

        assert_eq!(decoded.version, WORKER_PROTOCOL_VERSION);
        assert_eq!(
            decoded,
            WorkerEnvelope {
                version: WORKER_PROTOCOL_VERSION,
                message: WorkerRequest::PrepareSession {
                    request: SessionRequest {
                        username: "test".to_owned(),
                        session: session(kind),
                    },
                },
            }
        );
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

        assert_eq!(decoded.version, WORKER_PROTOCOL_VERSION);
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
fn worker_process_accepts_valid_request() {
    let input = format!(
        "{}\n",
        serde_json::to_string(&WorkerEnvelope {
            version: WORKER_PROTOCOL_VERSION,
            message: WorkerRequest::PrepareSession {
                request: SessionRequest {
                    username: "test".to_owned(),
                    session: session(SessionKind::Wayland),
                },
            },
        })
        .expect("request should serialize")
    );
    let mut reader = Cursor::new(input.into_bytes());
    let mut writer = Vec::new();

    run_worker_process(&mut reader, &mut writer).expect("worker should succeed");

    let decoded: WorkerEnvelope<WorkerResponse> =
        serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should deserialize");
    assert_eq!(
        decoded.message,
        WorkerResponse::Ready {
            session: StartedSession {
                username: "test".to_owned(),
                session: session(SessionKind::Wayland),
            },
        }
    );
}

#[test]
fn worker_process_rejects_invalid_version_and_json() {
    let invalid_version = format!(
        "{}\n",
        serde_json::to_string(&WorkerEnvelope {
            version: 999,
            message: WorkerRequest::PrepareSession {
                request: SessionRequest {
                    username: "test".to_owned(),
                    session: session(SessionKind::Wayland),
                },
            },
        })
        .expect("request should serialize")
    );
    let mut reader = Cursor::new(invalid_version.into_bytes());
    let mut writer = Vec::new();
    let error = run_worker_process(&mut reader, &mut writer)
        .expect_err("worker should reject unsupported version");
    assert_eq!(error, crate::SessionError::WorkerRejected);
    let version_response: WorkerEnvelope<WorkerResponse> =
        serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should deserialize");
    assert_eq!(
        version_response.message,
        WorkerResponse::Rejected {
            code: WorkerErrorCode::UnsupportedVersion,
        }
    );

    let mut reader = Cursor::new(b"{bad\n".to_vec());
    let mut writer = Vec::new();
    let error = run_worker_process(&mut reader, &mut writer)
        .expect_err("worker should reject invalid json");
    assert_eq!(error, crate::SessionError::WorkerRejected);
    let json_response: WorkerEnvelope<WorkerResponse> =
        serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should deserialize");
    assert_eq!(
        json_response.message,
        WorkerResponse::Rejected {
            code: WorkerErrorCode::InvalidRequest,
        }
    );
}
