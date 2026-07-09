use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{StartedSession, WorkerEnvelope, WorkerResponse};

fn main() {
    let payload = serde_json::to_string(&WorkerEnvelope {
        version: 999,
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
}
