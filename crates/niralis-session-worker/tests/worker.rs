use std::io::Write;
use std::process::{Command, Stdio};

use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{
    SessionRequest, StartedSession, WorkerEnvelope, WorkerErrorCode, WorkerRequest, WorkerResponse,
    WORKER_PROTOCOL_VERSION,
};

fn talk_to_worker(path: &str, payload: &[u8]) -> (std::process::ExitStatus, String) {
    let mut child = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("worker should spawn");

    child
        .stdin
        .take()
        .expect("stdin should exist")
        .write_all(payload)
        .expect("payload should write");

    let output = child.wait_with_output().expect("worker should exit");
    (
        output.status,
        String::from_utf8(output.stdout).expect("stdout should be utf8"),
    )
}

fn worker_bin() -> &'static str {
    env!("CARGO_BIN_EXE_niralis-session-worker")
}

fn valid_request() -> String {
    serde_json::to_string(&WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message: WorkerRequest::PrepareSession {
            request: SessionRequest {
                username: "test".to_owned(),
                session: SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: SessionKind::Wayland,
                },
            },
        },
    })
    .expect("request should serialize")
        + "\n"
}

#[test]
fn valid_request_returns_ready_and_preserves_session() {
    let (status, stdout) = talk_to_worker(worker_bin(), valid_request().as_bytes());
    let envelope: WorkerEnvelope<WorkerResponse> =
        serde_json::from_str(stdout.trim_end()).expect("response should parse");

    assert!(status.success());
    assert_eq!(envelope.version, WORKER_PROTOCOL_VERSION);
    assert_eq!(
        envelope.message,
        WorkerResponse::Ready {
            session: StartedSession {
                username: "test".to_owned(),
                session: SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: SessionKind::Wayland,
                },
            },
        }
    );
}

#[test]
fn invalid_version_returns_rejection() {
    let request = serde_json::to_string(&WorkerEnvelope {
        version: 999,
        message: WorkerRequest::PrepareSession {
            request: SessionRequest {
                username: "test".to_owned(),
                session: SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: SessionKind::Wayland,
                },
            },
        },
    })
    .expect("request should serialize")
        + "\n";

    let (status, stdout) = talk_to_worker(worker_bin(), request.as_bytes());
    let envelope: WorkerEnvelope<WorkerResponse> =
        serde_json::from_str(stdout.trim_end()).expect("response should parse");

    assert!(!status.success());
    assert_eq!(
        envelope.message,
        WorkerResponse::Rejected {
            code: WorkerErrorCode::UnsupportedVersion,
        }
    );
}

#[test]
fn malformed_json_is_rejected_without_panic() {
    let (status, stdout) = talk_to_worker(worker_bin(), b"{broken\n");
    let envelope: WorkerEnvelope<WorkerResponse> =
        serde_json::from_str(stdout.trim_end()).expect("response should parse");

    assert!(!status.success());
    assert_eq!(
        envelope.message,
        WorkerResponse::Rejected {
            code: WorkerErrorCode::InvalidRequest,
        }
    );
}

#[test]
fn oversized_request_is_rejected_without_panic() {
    let payload = format!("{}\n", "x".repeat((64 * 1024) + 1));
    let (status, stdout) = talk_to_worker(worker_bin(), payload.as_bytes());
    let envelope: WorkerEnvelope<WorkerResponse> =
        serde_json::from_str(stdout.trim_end()).expect("response should parse");

    assert!(!status.success());
    assert_eq!(
        envelope.message,
        WorkerResponse::Rejected {
            code: WorkerErrorCode::InvalidRequest,
        }
    );
}

#[test]
fn eof_without_request_is_rejected_without_panic() {
    let (status, stdout) = talk_to_worker(worker_bin(), b"");
    let envelope: WorkerEnvelope<WorkerResponse> =
        serde_json::from_str(stdout.trim_end()).expect("response should parse");

    assert!(!status.success());
    assert_eq!(
        envelope.message,
        WorkerResponse::Rejected {
            code: WorkerErrorCode::InvalidRequest,
        }
    );
}

#[test]
fn worker_responds_once_and_terminates() {
    let (status, stdout) = talk_to_worker(worker_bin(), valid_request().as_bytes());

    assert!(status.success());
    assert_eq!(stdout.lines().count(), 1);
}
