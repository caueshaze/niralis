use niralis_session::{
    read_control_request, read_envelope, WorkerControlRequest, WorkerEnvelope, WorkerRequest,
    WorkerResponse, WORKER_CONTROL_PROTOCOL_VERSION, WORKER_PROTOCOL_VERSION,
};
use std::io::Write;
use std::os::unix::net::UnixListener;

fn main() {
    run(std::env::args()
        .next()
        .is_some_and(|name| name.contains("stubborn")));
}

fn run(stubborn: bool) {
    let request: WorkerEnvelope<WorkerRequest> = read_envelope(&mut std::io::stdin()).unwrap();
    let (session, control_path, worker_id) = match request.message {
        WorkerRequest::PamSession {
            request,
            control_path,
            worker_id,
            ..
        } => (
            niralis_session::StartedSession {
                username: request.username,
                session: request.session,
            },
            control_path,
            worker_id,
        ),
        _ => std::process::exit(1),
    };
    let listener = UnixListener::bind(&control_path).unwrap();
    unsafe {
        libc::setsid();
    }
    let pid = std::process::id();
    serde_json::to_writer(
        &mut std::io::stdout(),
        &WorkerEnvelope {
            version: WORKER_PROTOCOL_VERSION,
            message: WorkerResponse::Started {
                session,
                session_pid: pid,
                session_pgid: pid,
                fixture_version: 1,
                worker_id,
            },
        },
    )
    .unwrap();
    std::io::stdout().write_all(b"\n").unwrap();
    std::io::stdout().flush().unwrap();
    eprintln!("fixture event=Started");
    let (mut stream, _) = listener.accept().unwrap();
    let control = read_control_request(&mut stream).unwrap();
    assert_eq!(control.version, WORKER_CONTROL_PROTOCOL_VERSION);
    assert!(matches!(
        control.message,
        WorkerControlRequest::Terminate { .. }
    ));
    eprintln!("fixture event=TerminationRequested");
    if stubborn {
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGTERM);
        }
        eprintln!("fixture event=SIGTERMIgnored");
        std::thread::sleep(std::time::Duration::from_secs(5));
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    } else {
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGTERM);
        }
    }
}
