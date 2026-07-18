use std::io::{BufWriter, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};

use niralis_session::{
    read_control_request, read_envelope, write_envelope, LogindSessionId, PayloadScopeIdentity,
    StartedSession, WorkerControlRequest, WorkerEnvelope, WorkerRequest, WorkerResponse,
    WORKER_CONTROL_PROTOCOL_VERSION,
};

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let request: WorkerEnvelope<WorkerRequest> =
        read_envelope(&mut std::io::stdin().lock()).map_err(|_| ())?;
    let WorkerRequest::PamSession {
        request,
        control_path,
        worker_id,
        ..
    } = request.message
    else {
        return Err(());
    };
    let listener = UnixListener::bind(&control_path).map_err(|_| ())?;
    let mut leader = spawn_payload()?;
    let mut remaining_member = spawn_payload()?;
    let logind_session_id = LogindSessionId::new("fixture-c1".to_owned()).ok_or(())?;
    let identity = PayloadScopeIdentity {
        unit_name: "niralis-payload-0123456789abcdef0123456789abcdef.scope".to_owned(),
        invocation_id: "0123456789abcdef0123456789abcdef".to_owned(),
        expected_uid: 1000,
        logind_session_id: logind_session_id.clone(),
    };
    let mut stdout = BufWriter::new(std::io::stdout().lock());
    write_envelope(
        &mut stdout,
        WorkerResponse::Preparing {
            worker_id: worker_id.clone(),
        },
    )
    .map_err(|_| ())?;
    write_envelope(
        &mut stdout,
        WorkerResponse::PayloadScopePrepared {
            worker_id: worker_id.clone(),
            expected_worker_pid: std::process::id(),
            session_pid: leader.id(),
            registration_nonce: identity.invocation_id.clone(),
            scope_identity: identity,
        },
    )
    .map_err(|_| ())?;
    stdout.flush().map_err(|_| ())?;
    let mut report = report_processes(leader.id(), remaining_member.id())?;
    let mut supervisor = unsafe { UnixStream::from_raw_fd(3) };
    let ack = read_control_request(&mut supervisor).map_err(|_| ())?;
    if ack.version != WORKER_CONTROL_PROTOCOL_VERSION
        || !matches!(
            ack.message,
            WorkerControlRequest::PayloadScopeRegistered {
                worker_id: ref ack_worker_id,
                expected_worker_pid,
                ..
            } if ack_worker_id == &worker_id && expected_worker_pid == std::process::id()
        )
    {
        return Err(());
    }
    writeln!(report, "ack").map_err(|_| ())?;
    if std::env::var_os("NIRALIS_SUPERVISOR_FIXTURE_POST_ACK_BARRIER").is_some() {
        let mut release = [0u8; 1];
        report.read_exact(&mut release).map_err(|_| ())?;
    }
    write_envelope(
        &mut stdout,
        WorkerResponse::Started {
            session: StartedSession {
                username: request.username,
                session: request.session,
            },
            session_pid: leader.id(),
            session_pgid: leader.id(),
            fixture_version: 2,
            worker_id: worker_id.clone(),
            logind_session_id,
        },
    )
    .map_err(|_| ())?;
    stdout.flush().map_err(|_| ())?;
    loop {
        let (mut control, _) = listener.accept().map_err(|_| ())?;
        let request = read_control_request(&mut control).map_err(|_| ())?;
        if request.version == WORKER_CONTROL_PROTOCOL_VERSION
            && matches!(
                request.message,
                WorkerControlRequest::Terminate {
                    worker_id: ref requested_worker_id,
                    expected_worker_pid,
                    ..
                } if requested_worker_id == &worker_id
                    && expected_worker_pid == std::process::id()
            )
        {
            terminate(&mut leader);
            terminate(&mut remaining_member);
            return Ok(());
        }
    }
}

fn spawn_payload() -> Result<Child, ()> {
    Command::new("/bin/sh")
        .args(["-c", "exec sleep 3600"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())
}

fn report_processes(leader: u32, member: u32) -> Result<UnixStream, ()> {
    let path = std::env::var_os("NIRALIS_SUPERVISOR_FIXTURE_SOCKET").ok_or(())?;
    let mut stream = UnixStream::connect(path).map_err(|_| ())?;
    writeln!(stream, "{} {leader} {member}", std::process::id()).map_err(|_| ())?;
    Ok(stream)
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
