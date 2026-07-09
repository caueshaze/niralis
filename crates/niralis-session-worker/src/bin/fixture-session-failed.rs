use niralis_session::{
    WorkerEnvelope, WorkerResponse, WorkerSessionFailureCode, WORKER_PROTOCOL_VERSION,
};

fn main() {
    let payload = serde_json::to_string(&WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message: WorkerResponse::SessionFailed {
            code: WorkerSessionFailureCode::OpenFailed,
        },
    })
    .expect("response should serialize");
    println!("{payload}");
    std::process::exit(1);
}
