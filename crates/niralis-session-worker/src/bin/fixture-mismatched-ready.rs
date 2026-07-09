use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{StartedSession, WorkerEnvelope, WorkerResponse, WORKER_PROTOCOL_VERSION};

fn main() {
    let payload = serde_json::to_string(&WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message: WorkerResponse::Ready {
            session: StartedSession {
                username: "root".to_owned(),
                session: SessionInfo {
                    id: "fake".to_owned(),
                    name: "Fake".to_owned(),
                    kind: SessionKind::X11,
                },
            },
        },
    })
    .expect("response should serialize");
    println!("{payload}");
}
