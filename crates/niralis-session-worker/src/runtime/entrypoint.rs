
pub fn run_worker_process_with_dependencies<
    R: Read,
    W: Write,
    F: WorkerAuthenticatorFactory,
    I: UnixIdentityResolver,
    G: SupplementaryGroupsResolver,
    C: SessionChildRunnerFactory,
    L: LogindSessionResolver,
>(
    reader: &mut R,
    writer: &mut W,
    dependencies: WorkerDependencies<'_, F, I, G, C, L>,
) -> Result<(), SessionError> {
    let envelope = match read_envelope::<WorkerRequest, _>(reader) {
        Ok(envelope) => envelope,
        Err(SessionError::WorkerProtocolFailed) => {
            debug!("worker rejected invalid request");
            write_rejection(writer, WorkerErrorCode::InvalidRequest)?;
            return Err(SessionError::WorkerRejected);
        }
        Err(_) => {
            debug!("worker failed while reading request");
            write_rejection(writer, WorkerErrorCode::InternalError)?;
            return Err(SessionError::WorkerRejected);
        }
    };
    if envelope.version != niralis_session::WORKER_PROTOCOL_VERSION {
        info!("worker rejected unsupported protocol version");
        write_rejection(writer, WorkerErrorCode::UnsupportedVersion)?;
        return Err(SessionError::WorkerRejected);
    }
    emit_fixture_event("RequestAccepted");

    match envelope.message {
        WorkerRequest::PrepareSession { request } => {
            info!(username = %request.username, session = %request.session.id, "worker prepared mock session");
            write_envelope(
                writer,
                WorkerResponse::Ready {
                    session: StartedSession {
                        username: request.username,
                        session: request.session,
                    },
                },
            )
        }
        WorkerRequest::PamSession {
            request,
            launch_plan,
            pam_service,
            password,
            session_child_path,
            session_probe_path,
            control_path,
            worker_id,
            launcher_pid,
        } => {
            if !control_path.as_os_str().is_empty()
                && !supervisor_peer_matches(internal_control_peer_uid(), launcher_pid)
            {
                warn!("dedicated supervisor channel peer validation failed");
                write_rejection(writer, WorkerErrorCode::InvalidRequest)?;
                return Err(SessionError::WorkerRejected);
            }
            if !control_path.as_os_str().is_empty() {
                write_envelope(
                    writer,
                    WorkerResponse::Preparing {
                        worker_id: worker_id.clone(),
                    },
                )?;
            }
            run_pam_session(
                writer,
                dependencies.authenticator_factory,
                dependencies.identity_resolver,
                dependencies.supplementary_groups_resolver,
                dependencies.session_child_runner_factory,
                dependencies.logind_resolver,
                request,
                pam_service,
                password,
                session_child_path,
                session_probe_path,
                control_path,
                worker_id,
                launcher_pid,
                dependencies.virtual_terminal_allocator,
                dependencies.runtime_dir_validator,
                dependencies.selinux_context_manager,
                dependencies.payload_scope_manager,
                dependencies.launch_phase_gate,
                launch_plan,
            )
        }
    }
}

include!("pam_session.rs");

fn valid_logind_identity(
    identity: &LogindSessionIdentity,
    uid: u32,
    expected_type: &str,
    desktop: &str,
    expected_seat: &str,
    expected_vtnr: u32,
) -> bool {
    identity.uid == uid
        && identity.session_type == expected_type
        && identity.class == "user"
        && identity
            .desktop
            .as_deref()
            .map_or(true, |value| value == desktop)
        && identity.seat.as_deref() == Some(expected_seat)
        && identity.vtnr == Some(expected_vtnr)
}

fn valid_terminal_proof(
    report: &crate::session_child::SessionChildReport,
    expected_seat: &str,
    expected_vtnr: u32,
) -> bool {
    report.terminal_proof.as_ref().is_some_and(|proof| {
        proof.seat == expected_seat
            && proof.vtnr == expected_vtnr
            && proof.fd == 3
            && proof.device_major == 4
            && proof.device_minor == expected_vtnr
            && proof.controlling_sid == report.process_identity.sid
            && proof.foreground_pgid == report.process_identity.pgid
    })
}

const SESSION_TERMINATION_GRACE: Duration = Duration::from_secs(5);
#[cfg(not(feature = "worker-test-fixtures"))]
const FORCED_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

fn pending_worker_signal() -> Result<Option<i32>, SessionError> {
    let fd = worker_signal_fd();
    if fd < 0 {
        return Ok(None);
    }
    crate::termination::read_signal_fd(fd).map_err(|_| SessionError::WorkerIoFailed)
}

fn bind_control_listener(path: &std::path::Path) -> Result<UnixListener, SessionError> {
    if !path.is_absolute() || path.exists() {
        return Err(SessionError::WorkerProtocolFailed);
    }
    let listener = UnixListener::bind(path).map_err(|_| SessionError::WorkerIoFailed)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| SessionError::WorkerIoFailed)?;
    Ok(listener)
}

fn wait_for_session(
    listener: Option<&UnixListener>,
    child_runner: &dyn crate::session_child::SessionChildRunner,
    worker_id: String,
    session_pid: u32,
    session_pgid: u32,
    authoritative_scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
) -> Result<SessionWaitResult, SessionError> {
    wait_for_session_with_grace(
        listener,
        child_runner,
        worker_id,
        session_pid,
        session_pgid,
        authoritative_scope,
        configured_session_termination_grace(),
        0,
    )
}
