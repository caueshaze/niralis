use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{StartedSession, WorkerEnvelope, WorkerResponse, WORKER_PROTOCOL_VERSION};
use std::io::Write;
use std::time::Duration;

fn main() {
    let session = StartedSession {
        username: "test".into(),
        session: SessionInfo {
            id: "niri".into(),
            name: "Niri".into(),
            kind: SessionKind::Wayland,
        },
    };
    let pid = std::process::id();
    let response = WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message: WorkerResponse::Started {
            session,
            session_pid: pid,
            session_pgid: pid,
            fixture_version: 1,
            worker_id: String::new(),
            logind_session_id: niralis_session::LogindSessionId::new("fixture-logind".to_owned())
                .unwrap(),
        },
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer(&mut out, &response).expect("started response should serialize");
    out.write_all(b"\n").expect("started response should flush");
    out.flush().expect("started response should flush");
    std::thread::sleep(Duration::from_secs(2));
}
