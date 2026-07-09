use niralis_session::{WorkerEnvelope, WorkerResponse, WORKER_PROTOCOL_VERSION};

fn main() {
    let payload = serde_json::to_string(&WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message: WorkerResponse::AuthenticationFailed,
    })
    .expect("response should serialize");
    println!("{payload}");
    std::process::exit(1);
}
