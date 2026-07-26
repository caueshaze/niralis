use niralis_session::{
    read_control_request, read_envelope, WorkerControlRequest, WorkerEnvelope, WorkerRequest,
    WorkerResponse, FIXTURE_SUPERVISOR_TRANSPORT_ENV, WORKER_CONTROL_PROTOCOL_VERSION,
    WORKER_PROTOCOL_VERSION,
};
use std::io::{Read, Write};

fn main() {
    run(std::env::args()
        .next()
        .is_some_and(|name| name.contains("stubborn")));
}

fn run(stubborn: bool) {
    let mut supervisor = fixture_transport_or_inherited_supervisor();
    eprintln!(
        "fixture event=ProtocolVersion:{} ControlVersion:{}",
        WORKER_PROTOCOL_VERSION, WORKER_CONTROL_PROTOCOL_VERSION
    );
    eprintln!("fixture event=SupervisorChannelReady");
    let request: WorkerEnvelope<WorkerRequest> = read_envelope(&mut std::io::stdin()).unwrap();
    eprintln!("fixture event=RequestRead");
    let (session, _control_path, worker_id, transaction) = match request.message {
        WorkerRequest::PamSession(niralis_session::WorkerPamSessionRequest {
            request,
            control_path,
            worker_id,
            transaction,
            ..
        }) => (
            niralis_session::StartedSession {
                username: request.username,
                session: request.session,
            },
            control_path,
            worker_id,
            transaction,
        ),
        _ => std::process::exit(1),
    };
    if unsafe { libc::setpgid(0, 0) } < 0 {
        eprintln!(
            "fixture-worker failure stage=setpgid errno={}",
            std::io::Error::last_os_error()
        );
        std::process::exit(71);
    }
    let pid = std::process::id();
    serde_json::to_writer(
        &mut std::io::stdout(),
        &WorkerEnvelope {
            version: WORKER_PROTOCOL_VERSION,
            message: WorkerResponse::Preparing {
                worker_id: worker_id.clone(),
                transaction: {
                    let mut value = (*transaction).clone();
                    value.stage = "preparing".into();
                    value
                },
            },
        },
    )
    .unwrap();
    std::io::stdout().write_all(b"\n").unwrap();
    std::io::stdout().flush().unwrap();
    eprintln!("fixture event=PreparingSent");
    let registration_nonce = "fixture-registration-nonce".to_owned();
    serde_json::to_writer(
        &mut std::io::stdout(),
        &WorkerEnvelope {
            version: WORKER_PROTOCOL_VERSION,
            message: WorkerResponse::PayloadScopePrepared {
                worker_id: worker_id.clone(),
                transaction: {
                    let mut value = (*transaction).clone();
                    value.stage = "scope_prepared".into();
                    value
                },
                expected_worker_pid: pid,
                session_pid: pid,
                registration_nonce: registration_nonce.clone(),
                scope_identity: niralis_session::PayloadScopeIdentity {
                    unit_name: format!("niralis-payload-{worker_id}.scope"),
                    invocation_id: "0123456789abcdef0123456789abcdef".to_owned(),
                    expected_uid: 1000,
                    logind_session_id: niralis_session::LogindSessionId::new(
                        "fixture-logind".to_owned(),
                    )
                    .unwrap(),
                },
            },
        },
    )
    .unwrap();
    std::io::stdout().write_all(b"\n").unwrap();
    std::io::stdout().flush().unwrap();
    eprintln!("fixture event=PreparedSent");
    let acknowledgement = read_control_request(&mut supervisor).unwrap();
    eprintln!("fixture event=ScopeAckReceived");
    assert_eq!(acknowledgement.version, WORKER_CONTROL_PROTOCOL_VERSION);
    assert!(matches!(
        acknowledgement.message,
        WorkerControlRequest::PayloadScopeRegistered {
            transaction: ack_transaction,
            worker_id: ack_worker_id,
            expected_worker_pid,
            registration_nonce: ack_nonce,
        }
        if ack_worker_id == worker_id
            && expected_worker_pid == pid
            && ack_nonce == registration_nonce
            && ack_transaction.matches_worker(&transaction, "scope_registered", 1)
    ));
    eprintln!("fixture event=ScopeAckTransactionAccepted");
    serde_json::to_writer(
        &mut std::io::stdout(),
        &WorkerEnvelope {
            version: WORKER_PROTOCOL_VERSION,
            message: WorkerResponse::Started {
                session,
                session_pid: pid,
                session_pgid: pid,
                fixture_version: 1,
                worker_id: worker_id.clone(),
                logind_session_id: niralis_session::LogindSessionId::new(
                    "fixture-logind".to_owned(),
                )
                .unwrap(),
                transaction: {
                    let mut value = *transaction;
                    value.stage = "started".into();
                    value
                },
            },
        },
    )
    .unwrap();
    std::io::stdout().write_all(b"\n").unwrap();
    std::io::stdout().flush().unwrap();
    eprintln!("fixture event=Started");
    eprintln!("fixture event=WaitingForTerminate worker_id={worker_id} pid={pid}");
    let control = read_control_request(&mut supervisor).unwrap();
    eprintln!("fixture event=TerminateReceived");
    assert_eq!(control.version, WORKER_CONTROL_PROTOCOL_VERSION);
    assert!(matches!(
        control.message,
        WorkerControlRequest::Terminate {
            worker_id: requested_worker_id,
            expected_worker_pid,
            expected_session_pid,
            expected_session_pgid,
        }
        if requested_worker_id == worker_id
            && expected_worker_pid == pid
            && expected_session_pid == pid
            && expected_session_pgid == unsafe { libc::getpgrp() as u32 }
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

fn fixture_transport_or_inherited_supervisor() -> Box<dyn Read> {
    #[cfg(feature = "worker-test-fixtures")]
    if std::env::var_os(FIXTURE_SUPERVISOR_TRANSPORT_ENV).is_some() {
        eprintln!("fixture event=Transport:FixturePipe");
        let transport = niralis_session_worker::take_fixture_supervisor_transport_for_test()
            .unwrap_or_else(|error| {
                eprintln!(
                    "fixture-worker failure stage=fixture-supervisor-transport cause={error:?}"
                );
                std::process::exit(70);
            });
        return Box::new(transport);
    }

    #[cfg(not(feature = "worker-test-fixtures"))]
    if std::env::var_os(FIXTURE_SUPERVISOR_TRANSPORT_ENV).is_some() {
        eprintln!(
            "fixture-worker failure stage=fixture-supervisor-transport cause=feature-disabled"
        );
        std::process::exit(70);
    }

    let supervisor = niralis_session_worker::diagnose_inherited_supervisor_channel()
        .unwrap_or_else(|error| {
            let fd_value = std::env::var_os(niralis_session::WORKER_SUPERVISOR_FD_ENV)
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<missing>".to_owned());
            let fd_path = fd_value
                .parse::<i32>()
                .ok()
                .map(|fd| format!("/proc/self/fd/{fd}"))
                .unwrap_or_else(|| "<invalid-fd>".to_owned());
            let fd_target = std::fs::read_link(&fd_path)
                .ok()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<unreadable>".to_owned());
            eprintln!(
                "fixture-worker failure stage=inherited-supervisor-channel cause={error:?} fd={fd_value} target={fd_target}"
            );
            match niralis_session_worker::probe_af_unix_environment_support() {
                niralis_session_worker::AfUnixEnvironmentProbe::Supported => {}
                probe => eprintln!("fixture-worker af_unix_probe={probe:?}"),
            }
            std::process::exit(70);
        });
    eprintln!("fixture event=Transport:InheritedSupervisorSocketpair");
    Box::new(supervisor)
}
