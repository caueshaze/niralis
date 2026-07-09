use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{StartedSession, WorkerEnvelope, WorkerResponse, WORKER_PROTOCOL_VERSION};

fn main() {
    let payload = serde_json::to_string(&WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message: WorkerResponse::Ready {
            session: StartedSession {
                username: "test".to_owned(),
                session: SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: SessionKind::Wayland,
                },
            },
        },
    })
    .expect("response should serialize");
    println!("{payload}");
    std::thread::park();
}
