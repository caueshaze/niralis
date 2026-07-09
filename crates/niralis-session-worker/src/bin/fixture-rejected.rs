use niralis_session::{WorkerEnvelope, WorkerErrorCode, WorkerResponse, WORKER_PROTOCOL_VERSION};

fn main() {
    let payload = serde_json::to_string(&WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message: WorkerResponse::Rejected {
            code: WorkerErrorCode::InternalError,
        },
    })
    .expect("response should serialize");
    println!("{payload}");
    std::process::exit(1);
}
