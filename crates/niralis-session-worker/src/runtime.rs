use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::thread;
use std::time::Duration;

use niralis_auth::{AuthError, Authenticator, PamAuthenticator};
use niralis_session::{
    read_control_request, read_envelope, write_envelope, SessionError, StartedSession,
    WorkerControlRequest, WorkerErrorCode, WorkerRequest, WorkerResponse, WorkerSessionFailureCode,
    WORKER_CONTROL_PROTOCOL_VERSION,
};
use tracing::{debug, info, warn};

use crate::identity::{
    NssSupplementaryGroupsResolver, NssUnixIdentityResolver, ResolvedUnixCredentials,
    SupplementaryGroupsResolver, UnixIdentityResolver,
};
use crate::logind::{LogindSessionIdentity, LogindSessionResolver, SdLoginResolver};
use crate::privilege_drop::PrivilegeDropTarget;
use crate::session_child::{
    ProcessSessionChildRunnerFactory, SessionChildExpectation, SessionChildRunnerFactory,
    SessionChildRuntimeContext, SessionChildTerminalContext, SessionChildUnixPath,
};
use crate::vt::{LinuxVirtualTerminalAllocator, VirtualTerminalAllocator, VirtualTerminalGuard};

pub trait WorkerAuthenticatorFactory: Send + Sync {
    fn build(&self, pam_service: &str) -> Box<dyn Authenticator>;
}

pub struct WorkerDependencies<'a, F, I, G, C, L> {
    pub authenticator_factory: &'a F,
    pub identity_resolver: &'a I,
    pub supplementary_groups_resolver: &'a G,
    pub session_child_runner_factory: &'a C,
    pub logind_resolver: &'a L,
    pub virtual_terminal_allocator: &'a dyn VirtualTerminalAllocator,
}

#[derive(Debug, Default)]
pub struct PamAuthenticatorFactory;

impl WorkerAuthenticatorFactory for PamAuthenticatorFactory {
    fn build(&self, pam_service: &str) -> Box<dyn Authenticator> {
        Box::new(PamAuthenticator::new(pam_service))
    }
}

pub fn run_worker_process<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), SessionError> {
    run_worker_process_with_dependencies(
        reader,
        writer,
        WorkerDependencies {
            authenticator_factory: &PamAuthenticatorFactory,
            identity_resolver: &NssUnixIdentityResolver,
            supplementary_groups_resolver: &NssSupplementaryGroupsResolver,
            session_child_runner_factory: &ProcessSessionChildRunnerFactory,
            logind_resolver: &SdLoginResolver,
            virtual_terminal_allocator: &LinuxVirtualTerminalAllocator,
        },
    )
}

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
            pam_service,
            password,
            session_child_path,
            session_probe_path,
            control_path,
            worker_id,
        } => run_pam_session(
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
            dependencies.virtual_terminal_allocator,
        ),
    }
}

fn run_pam_session<
    W: Write,
    F: WorkerAuthenticatorFactory,
    I: UnixIdentityResolver,
    G: SupplementaryGroupsResolver,
    C: SessionChildRunnerFactory,
    L: LogindSessionResolver,
>(
    writer: &mut W,
    factory: &F,
    identity_resolver: &I,
    supplementary_groups_resolver: &G,
    session_child_runner_factory: &C,
    logind_resolver: &L,
    request: niralis_session::SessionRequest,
    pam_service: String,
    password: niralis_session::WorkerSecret,
    session_child_path: std::path::PathBuf,
    session_probe_path: std::path::PathBuf,
    control_path: std::path::PathBuf,
    worker_id: String,
    virtual_terminal_allocator: &dyn VirtualTerminalAllocator,
) -> Result<(), SessionError> {
    let control_listener = if control_path.as_os_str().is_empty() {
        None
    } else {
        Some(bind_control_listener(&control_path)?)
    };
    let seat = niralis_auth::SeatId::new("seat0".to_owned())
        .ok_or(SessionError::AuthenticatedSessionFailed)?;
    let mut terminal = match virtual_terminal_allocator.allocate(&seat) {
        Ok(terminal) => VirtualTerminalGuard::new(terminal),
        Err(error) => {
            warn!(username = %request.username, session = %request.session.id, ?error, "worker failed to allocate virtual terminal");
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::OpenFailed,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
    };
    let authenticator = factory.build(&pam_service);
    let auth_result = authenticator.authenticate(&request.username, password.expose());
    drop(password);
    let mut transaction = match auth_result {
        Ok(transaction) => transaction,
        Err(AuthError::LoginFailed) => {
            info!(username = %request.username, session = %request.session.id, "worker PAM authentication failed");
            write_envelope(writer, WorkerResponse::AuthenticationFailed)?;
            return Err(SessionError::AuthenticationFailed);
        }
        Err(AuthError::InfrastructureFailed) => {
            warn!(
                username = %request.username,
                session = %request.session.id,
                "worker PAM infrastructure failed before authentication completed"
            );
            write_rejection(writer, WorkerErrorCode::InternalError)?;
            return Err(SessionError::WorkerRejected);
        }
        Err(AuthError::AuthenticatedIdentityUnavailable) => {
            warn!(
                username = %request.username,
                session = %request.session.id,
                "worker could not determine PAM authenticated identity"
            );
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::PamIdentityUnavailable,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
    };
    let pam_username = transaction.user().username.clone();
    let identity = match identity_resolver.resolve(&pam_username) {
        Ok(identity) => identity,
        Err(error) => {
            warn!(
                username = %pam_username,
                session = %request.session.id,
                ?error,
                "worker failed to resolve canonical Unix identity"
            );
            drop(transaction);
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::IdentityResolutionFailed,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
    };
    let supplementary_gids = match supplementary_groups_resolver.resolve(&identity) {
        Ok(groups) => groups,
        Err(error) => {
            warn!(
                username = %identity.username,
                session = %request.session.id,
                ?error,
                "worker failed to resolve supplementary Unix groups"
            );
            drop(transaction);
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::SupplementaryGroupsResolutionFailed,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
    };
    let credentials = ResolvedUnixCredentials {
        identity,
        supplementary_gids,
    };
    debug!(
        username = %credentials.identity.username,
        uid = credentials.identity.uid,
        gid = credentials.identity.gid,
        supplementary_group_count = credentials.supplementary_gids.len(),
        "resolved canonical Unix credentials"
    );
    let canonical_username = credentials.identity.username.clone();

    let expected_type = match request.session.kind {
        niralis_protocol::SessionKind::Wayland => "wayland",
        niralis_protocol::SessionKind::X11 => "x11",
    };
    let metadata = niralis_auth::PamSessionMetadata {
        session_type: match request.session.kind {
            niralis_protocol::SessionKind::Wayland => niralis_auth::PamSessionType::Wayland,
            niralis_protocol::SessionKind::X11 => niralis_auth::PamSessionType::X11,
        },
        session_class: niralis_auth::PamSessionClass::User,
        session_desktop: request.session.id.clone(),
        seat: Some(terminal.lease().seat().clone()),
        vtnr: Some(terminal.lease().vtnr()),
    };
    let open_result = catch_unwind(AssertUnwindSafe(|| transaction.open_session(&metadata)));
    let session = StartedSession {
        username: request.username,
        session: request.session,
    };

    match open_result {
        Ok(Ok(())) => {
            info!(username = %canonical_username, session = %session.session.id, "worker PAM session opened");
            let logind = match logind_resolver.resolve_by_pid(std::process::id()) {
                Ok(Some(identity))
                    if valid_logind_identity(
                        &identity,
                        credentials.identity.uid,
                        expected_type,
                        &session.session.id,
                        terminal.lease().seat().as_str(),
                        terminal.lease().vtnr().number(),
                    ) =>
                {
                    identity
                }
                _ => {
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::LogindFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            let child_terminal_fd = match terminal.lease().duplicate_terminal_fd() {
                Ok(fd) => fd,
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker failed to duplicate owned VT fd");
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::SessionChildFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            let child_runner = match session_child_runner_factory
                .build_with_terminal(Path::new(&session_child_path), Some(child_terminal_fd))
            {
                Ok(runner) => runner,
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker failed to build session child runner");
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::SessionChildFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            let runtime = match (
                SessionChildUnixPath::new(&credentials.identity.home),
                SessionChildUnixPath::new(&credentials.identity.shell),
                SessionChildUnixPath::new(&session_probe_path),
            ) {
                (Ok(home), Ok(shell), Ok(probe_path)) => SessionChildRuntimeContext {
                    home,
                    shell,
                    session_type: match session.session.kind {
                        niralis_protocol::SessionKind::Wayland => "wayland",
                        niralis_protocol::SessionKind::X11 => "x11",
                    }
                    .to_owned(),
                    probe_path,
                },
                _ => {
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::SessionChildFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            let child_report = match child_runner.run_child(SessionChildExpectation {
                canonical_username: canonical_username.clone(),
                session_id: session.session.id.clone(),
                target_credentials: PrivilegeDropTarget::from(&credentials),
                runtime,
                terminal: Some(SessionChildTerminalContext {
                    seat: terminal.lease().seat().as_str().to_owned(),
                    vtnr: terminal.lease().vtnr().number(),
                    fd: 3,
                    device_major: 4,
                    device_minor: terminal.lease().vtnr().number(),
                }),
            }) {
                Ok(report) => report,
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker session child failed");
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::SessionChildFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            if !valid_terminal_proof(
                &child_report,
                terminal.lease().seat().as_str(),
                terminal.lease().vtnr().number(),
            ) {
                let _ = child_runner.terminate(SESSION_TERMINATION_GRACE);
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            match logind_resolver.resolve_by_pid(child_report.child_pid) {
                Ok(Some(child_identity))
                    if child_identity.id == logind.id
                        && valid_logind_identity(
                            &child_identity,
                            credentials.identity.uid,
                            expected_type,
                            &session.session.id,
                            terminal.lease().seat().as_str(),
                            terminal.lease().vtnr().number(),
                        ) => {}
                _ => {
                    let _ = child_runner.terminate(SESSION_TERMINATION_GRACE);
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::LogindFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            }
            if terminal
                .lease_mut()
                .activate(Duration::from_millis(1000))
                .is_err()
            {
                let _ = child_runner.terminate(SESSION_TERMINATION_GRACE);
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            info!(
                username = %canonical_username,
                session = %session.session.id,
                pid = child_report.child_pid,
                spawned_child_pid = child_report.child_pid,
                exec_probe_pid = child_report.process_identity.pid,
                sid = child_report.process_identity.sid,
                pgid = child_report.process_identity.pgid,
                sid_equals_pid = child_report.process_identity.sid == child_report.child_pid,
                pgid_equals_pid = child_report.process_identity.pgid == child_report.child_pid,
                uid = child_report.applied_credentials.uid,
                gid = child_report.applied_credentials.gid,
                supplementary_group_count = child_report.applied_credentials.supplementary_gids.len(),
                effective_capability_count = child_report.isolation_proof.capabilities.effective.len(),
                permitted_capability_count = child_report.isolation_proof.capabilities.permitted.len(),
                inheritable_capability_count = child_report.isolation_proof.capabilities.inheritable.len(),
                ambient_capability_count = child_report.isolation_proof.capabilities.ambient.len(),
                bounding_capability_count = child_report.isolation_proof.capabilities.bounding.len(),
                securebits = child_report.isolation_proof.securebits,
                no_new_privs = child_report.isolation_proof.no_new_privs,
                open_fd_count = child_report.isolation_proof.open_fds.len(),
                cwd_matches_home = child_report.runtime_environment.cwd == child_report.runtime_environment.home,
                runtime_session_type = %child_report.runtime_environment.session_type,
                probe_version = child_report.exec_probe_version,
                "worker session exec probe verified"
            );
            write_envelope(
                writer,
                WorkerResponse::Started {
                    session: session.clone(),
                    session_pid: child_report.child_pid,
                    session_pgid: child_report.process_identity.pgid,
                    fixture_version: child_report.exec_probe_version,
                    worker_id: worker_id.clone(),
                    logind_session_id: niralis_session::LogindSessionId::new(
                        logind.id.as_str().to_owned(),
                    )
                    .expect("validated logind id"),
                },
            )?;
            info!(username = %canonical_username, session = %session.session.id, pid = child_report.child_pid, "worker session started; PAM transaction remains open");
            let child_status = match wait_for_session(
                control_listener,
                child_runner.as_ref(),
                worker_id,
                child_report.child_pid,
                child_report.process_identity.pgid,
            ) {
                Ok(status) => status,
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker failed while waiting for session child");
                    drop(transaction);
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            info!(username = %canonical_username, session = %session.session.id, ?child_status, "worker session child reaped");
            drop(transaction);
            info!(username = %canonical_username, session = %session.session.id, "worker PAM transaction closed");
            let _ = terminal.release();
            if child_status.success() {
                Ok(())
            } else {
                Err(SessionError::AuthenticatedSessionFailed)
            }
        }
        Ok(Err(_)) => {
            warn!(username = %canonical_username, session = %session.session.id, "worker PAM session open failed");
            drop(transaction);
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::OpenFailed,
                },
            )?;
            Err(SessionError::AuthenticatedSessionFailed)
        }
        Err(_) => {
            warn!(username = %canonical_username, session = %session.session.id, "worker PAM session open panicked");
            drop(transaction);
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::InternalPanic,
                },
            )?;
            Err(SessionError::AuthenticatedSessionFailed)
        }
    }
}

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
    listener: Option<UnixListener>,
    child_runner: &dyn crate::session_child::SessionChildRunner,
    worker_id: String,
    session_pid: u32,
    session_pgid: u32,
) -> Result<std::process::ExitStatus, SessionError> {
    loop {
        if let Some(status) = child_runner
            .poll_child()
            .map_err(|_| SessionError::AuthenticatedSessionFailed)?
        {
            return Ok(status);
        }
        if let Some(listener) = listener.as_ref() {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if !peer_is_root(&stream) {
                        continue;
                    }
                    let request = read_control_request(&mut stream)
                        .map_err(|_| SessionError::AuthenticatedSessionFailed)?;
                    if request.version != WORKER_CONTROL_PROTOCOL_VERSION {
                        return Err(SessionError::AuthenticatedSessionFailed);
                    }
                    match request.message {
                        WorkerControlRequest::Terminate {
                            worker_id: requested_worker_id,
                            expected_worker_pid,
                            expected_session_pid,
                            expected_session_pgid,
                        } if requested_worker_id == worker_id
                            && expected_worker_pid == std::process::id()
                            && expected_session_pid == session_pid
                            && expected_session_pgid == session_pgid =>
                        {
                            info!("worker session termination requested");
                            return child_runner
                                .terminate(SESSION_TERMINATION_GRACE)
                                .map_err(|_| SessionError::AuthenticatedSessionFailed);
                        }
                        _ => return Err(SessionError::AuthenticatedSessionFailed),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(SessionError::AuthenticatedSessionFailed),
            }
        } else {
            return child_runner
                .wait_for_child()
                .map_err(|_| SessionError::AuthenticatedSessionFailed);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn peer_is_root(stream: &UnixStream) -> bool {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        )
    };
    result == 0 && credentials.uid == 0
}

#[cfg(test)]
mod terminal_binding_tests {
    use super::*;

    fn identity() -> LogindSessionIdentity {
        LogindSessionIdentity {
            id: crate::LogindSessionId::new("c1".to_owned()).unwrap(),
            uid: 1000,
            session_type: "wayland".to_owned(),
            class: "user".to_owned(),
            desktop: Some("niri".to_owned()),
            seat: Some("seat0".to_owned()),
            vtnr: Some(2),
        }
    }

    #[test]
    fn logind_seat_and_vt_are_bound_to_the_owned_terminal() {
        let identity = identity();
        assert!(valid_logind_identity(
            &identity, 1000, "wayland", "niri", "seat0", 2
        ));
        assert!(!valid_logind_identity(
            &identity, 1000, "wayland", "niri", "seat1", 2
        ));
        assert!(!valid_logind_identity(
            &identity, 1000, "wayland", "niri", "seat0", 3
        ));
    }
}

fn write_rejection<W: Write>(writer: &mut W, code: WorkerErrorCode) -> Result<(), SessionError> {
    write_envelope(writer, WorkerResponse::Rejected { code })
}
