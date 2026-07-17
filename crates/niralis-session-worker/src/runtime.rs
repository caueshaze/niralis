use std::cell::Cell;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(feature = "worker-test-fixtures")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
use crate::selinux::{LinuxSelinuxContextManager, SelinuxContextManager};
use crate::session_child::{
    ProcessSessionChildRunnerFactory, SessionChildExpectation, SessionChildRunnerFactory,
    SessionChildRuntimeContext, SessionChildTerminalContext, SessionChildUnixPath,
};
use crate::smoke::authorize_real_graphical_smoke_for_runtime;
use crate::vt::{LinuxVirtualTerminalAllocator, VirtualTerminalAllocator, VirtualTerminalGuard};

pub trait WorkerAuthenticatorFactory: Send + Sync {
    fn build(&self, pam_service: &str) -> Box<dyn Authenticator>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerLaunchPhase {
    PendingHandoffBeforeScope,
    ScopePinnedBeforeAck,
    AckReceivedBeforeCommitExec,
}

pub(crate) trait LaunchPhaseGate: Send + Sync {
    fn reached(&self, phase: WorkerLaunchPhase) -> Result<(), SessionError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NoopLaunchPhaseGate;

impl LaunchPhaseGate for NoopLaunchPhaseGate {
    fn reached(&self, _phase: WorkerLaunchPhase) -> Result<(), SessionError> {
        Ok(())
    }
}

pub struct WorkerDependencies<'a, F, I, G, C, L> {
    pub authenticator_factory: &'a F,
    pub identity_resolver: &'a I,
    pub supplementary_groups_resolver: &'a G,
    pub session_child_runner_factory: &'a C,
    pub logind_resolver: &'a L,
    pub virtual_terminal_allocator: &'a dyn VirtualTerminalAllocator,
    pub runtime_dir_validator: &'a dyn RuntimeDirValidator,
    pub selinux_context_manager: &'a dyn SelinuxContextManager,
    pub payload_scope_manager: &'a dyn crate::payload_scope::PayloadScopeManager,
    pub launch_phase_gate: &'a dyn LaunchPhaseGate,
}

pub trait RuntimeDirValidator: Send + Sync {
    fn validate(&self, path: &Path, uid: u32) -> Result<(), RuntimeDirValidationError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxRuntimeDirValidator;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RuntimeDirValidationError {
    #[error("runtime directory path is invalid")]
    InvalidPath,
    #[error("runtime directory metadata is invalid")]
    InvalidMetadata,
    #[error("runtime directory owner or mode is invalid")]
    WrongOwnerOrMode,
}

impl RuntimeDirValidator for LinuxRuntimeDirValidator {
    fn validate(&self, path: &Path, uid: u32) -> Result<(), RuntimeDirValidationError> {
        if !path.is_absolute() {
            return Err(RuntimeDirValidationError::InvalidPath);
        }
        let link = std::fs::symlink_metadata(path)
            .map_err(|_| RuntimeDirValidationError::InvalidMetadata)?;
        if link.file_type().is_symlink() || !link.is_dir() {
            return Err(RuntimeDirValidationError::InvalidMetadata);
        }
        let metadata =
            std::fs::metadata(path).map_err(|_| RuntimeDirValidationError::InvalidMetadata)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != uid
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(RuntimeDirValidationError::WrongOwnerOrMode);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct StubRuntimeDirValidator;

impl RuntimeDirValidator for StubRuntimeDirValidator {
    fn validate(&self, _path: &Path, _uid: u32) -> Result<(), RuntimeDirValidationError> {
        Ok(())
    }
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
            runtime_dir_validator: &LinuxRuntimeDirValidator,
            selinux_context_manager: &LinuxSelinuxContextManager,
            payload_scope_manager: &crate::payload_scope::SystemdPayloadScopeManager,
            launch_phase_gate: &NoopLaunchPhaseGate,
        },
    )
}

thread_local! {
    static WORKER_SIGNAL_FD: Cell<i32> = const { Cell::new(-1) };
    static SUPERVISOR_CHANNEL_FD: Cell<i32> = const { Cell::new(-1) };
}

#[cfg(feature = "worker-test-fixtures")]
static FIXTURE_GRACE_MILLIS: AtomicU64 = AtomicU64::new(5_000);
#[cfg(feature = "worker-test-fixtures")]
static FIXTURE_WATCHDOG_AUTHORIZED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "worker-test-fixtures")]
static FIXTURE_CONTROL_UID: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "worker-test-fixtures")]
pub(crate) fn set_fixture_grace_period(duration: Duration) {
    let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    FIXTURE_GRACE_MILLIS.store(millis.max(1), Ordering::SeqCst);
}

#[cfg(feature = "worker-test-fixtures")]
pub(crate) fn authorize_fixture_launch_watchdog() {
    FIXTURE_WATCHDOG_AUTHORIZED.store(true, Ordering::SeqCst);
}

#[cfg(feature = "worker-test-fixtures")]
pub(crate) fn set_fixture_control_uid(uid: u32) {
    FIXTURE_CONTROL_UID.store(u64::from(uid), Ordering::SeqCst);
}

fn internal_control_peer_uid() -> u32 {
    #[cfg(feature = "worker-test-fixtures")]
    {
        u32::try_from(FIXTURE_CONTROL_UID.load(Ordering::SeqCst)).unwrap_or(0)
    }
    #[cfg(not(feature = "worker-test-fixtures"))]
    {
        0
    }
}

fn authorize_launch_watchdog(
    session_id: &str,
) -> Result<Duration, crate::smoke::RealGraphicalSmokeGuardError> {
    #[cfg(feature = "worker-test-fixtures")]
    if FIXTURE_WATCHDOG_AUTHORIZED.load(Ordering::SeqCst) {
        return Ok(Duration::from_secs(300));
    }
    authorize_real_graphical_smoke_for_runtime(session_id)
}

fn configured_session_termination_grace() -> Duration {
    #[cfg(feature = "worker-test-fixtures")]
    {
        Duration::from_millis(FIXTURE_GRACE_MILLIS.load(Ordering::SeqCst))
    }
    #[cfg(not(feature = "worker-test-fixtures"))]
    {
        SESSION_TERMINATION_GRACE
    }
}

fn emit_fixture_event(event: &str) {
    #[cfg(feature = "worker-test-fixtures")]
    crate::full_worker_fixture::emit_fixture_event(event);

    #[cfg(not(feature = "worker-test-fixtures"))]
    let _ = event;
}

fn emit_fixture_cause(cause: &crate::termination::TerminationCause) {
    use crate::termination::{TerminationCause, WorkerTerminationSignal};

    let event = match cause {
        TerminationCause::WorkerSignal(WorkerTerminationSignal::Sigterm) => "Cause:Sigterm",
        TerminationCause::WorkerSignal(WorkerTerminationSignal::Sigint) => "Cause:Sigint",
        TerminationCause::WorkerSignal(WorkerTerminationSignal::Sighup) => "Cause:Sighup",
        TerminationCause::SupervisorDisconnected => "Cause:SupervisorDisconnected",
        TerminationCause::InternalTerminateRequest => "Cause:InternalTerminateRequest",
        TerminationCause::LeaderExited(_) => "Cause:LeaderExited",
        TerminationCause::RuntimeFailure => "Cause:RuntimeFailure",
    };
    emit_fixture_event(event);
}

fn emit_fixture_launch_signal(signal: i32) {
    let name = match signal {
        libc::SIGTERM => "SIGTERM",
        libc::SIGINT => "SIGINT",
        libc::SIGHUP => "SIGHUP",
        _ => "UNKNOWN",
    };
    emit_fixture_event(&format!("LaunchCancellationSignal:{name}"));
}

fn worker_signal_fd() -> i32 {
    WORKER_SIGNAL_FD.get()
}
fn supervisor_channel_fd() -> i32 {
    SUPERVISOR_CHANNEL_FD.get()
}
fn set_worker_signal_fd(fd: i32) -> i32 {
    WORKER_SIGNAL_FD.replace(fd)
}
fn set_supervisor_channel_fd(fd: i32) -> i32 {
    SUPERVISOR_CHANNEL_FD.replace(fd)
}

fn duplicate_supervisor_channel() -> Result<UnixStream, SessionError> {
    let fd = supervisor_channel_fd();
    if fd < 0 {
        return Err(SessionError::WorkerProtocolFailed);
    }
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(SessionError::WorkerIoFailed);
    }
    Ok(unsafe { UnixStream::from_raw_fd(duplicate) })
}

fn supervisor_peer_matches(expected_uid: u32, expected_pid: u32) -> bool {
    duplicate_supervisor_channel()
        .ok()
        .and_then(|stream| peer_credentials(&stream))
        .is_some_and(|credentials| {
            credentials.uid == expected_uid && credentials.pid as u32 == expected_pid
        })
}

pub fn run_worker_process_with_signals<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    signals: &crate::termination::WorkerSignalFd,
    supervisor_fd: RawFd,
) -> Result<(), SessionError> {
    run_worker_process_with_dependencies_and_signals(
        reader,
        writer,
        signals,
        supervisor_fd,
        WorkerDependencies {
            authenticator_factory: &PamAuthenticatorFactory,
            identity_resolver: &NssUnixIdentityResolver,
            supplementary_groups_resolver: &NssSupplementaryGroupsResolver,
            session_child_runner_factory: &ProcessSessionChildRunnerFactory,
            logind_resolver: &SdLoginResolver,
            virtual_terminal_allocator: &LinuxVirtualTerminalAllocator,
            runtime_dir_validator: &LinuxRuntimeDirValidator,
            selinux_context_manager: &LinuxSelinuxContextManager,
            payload_scope_manager: &crate::payload_scope::SystemdPayloadScopeManager,
            launch_phase_gate: &NoopLaunchPhaseGate,
        },
    )
}

pub(crate) fn run_worker_process_with_dependencies_and_signals<
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
    signals: &crate::termination::WorkerSignalFd,
    supervisor_fd: RawFd,
    dependencies: WorkerDependencies<'_, F, I, G, C, L>,
) -> Result<(), SessionError> {
    let previous = set_worker_signal_fd(signals.as_raw_fd());
    let previous_supervisor = set_supervisor_channel_fd(supervisor_fd);
    let result = run_worker_process_with_dependencies(reader, writer, dependencies);
    set_worker_signal_fd(previous);
    set_supervisor_channel_fd(previous_supervisor);
    result
}

pub fn take_inherited_supervisor_channel() -> Result<UnixStream, SessionError> {
    let value = std::env::var_os(niralis_session::WORKER_SUPERVISOR_FD_ENV)
        .ok_or(SessionError::WorkerProtocolFailed)?;
    std::env::remove_var(niralis_session::WORKER_SUPERVISOR_FD_ENV);
    let fd = value
        .to_str()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or(SessionError::WorkerProtocolFailed)?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(SessionError::WorkerProtocolFailed);
    }
    let mut socket_type: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
        || socket_type != libc::SOCK_STREAM
    {
        return Err(SessionError::WorkerProtocolFailed);
    }
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
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
    launcher_pid: u32,
    virtual_terminal_allocator: &dyn VirtualTerminalAllocator,
    runtime_dir_validator: &dyn RuntimeDirValidator,
    selinux_context_manager: &dyn SelinuxContextManager,
    payload_scope_manager: &dyn crate::payload_scope::PayloadScopeManager,
    launch_phase_gate: &dyn LaunchPhaseGate,
    launch_plan: niralis_session::SessionExecPlan,
) -> Result<(), SessionError> {
    if launch_plan.validate().is_err() {
        write_envelope(
            writer,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::LaunchSpecMalformed,
            },
        )?;
        return Err(SessionError::AuthenticatedSessionFailed);
    }
    let executable =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(launch_plan.executable.clone()));
    let executable_metadata = std::fs::metadata(&executable);
    let executable_ok = executable_metadata
        .as_ref()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if !executable_ok {
        write_envelope(
            writer,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::ExecutableUnavailable,
            },
        )?;
        return Err(SessionError::AuthenticatedSessionFailed);
    }
    let watchdog = match authorize_launch_watchdog(&request.session.id) {
        Ok(duration) => duration,
        Err(error) => {
            warn!(session = %request.session.id, ?error, "real graphical session rejected before PAM");
            write_rejection(writer, WorkerErrorCode::RealGraphicalSessionNotAuthorized)?;
            return Err(SessionError::WorkerRejected);
        }
    };
    // pam_systemd deliberately returns PAM_SUCCESS without creating a session
    // when the calling PID is already a member of one. A daemon started via
    // ssh -> sudo inherits that session cgroup, and env_clear() cannot change
    // it. Fail before acquiring a VT or beginning PAM so this is explicit.
    match logind_resolver.resolve_by_pid(std::process::id()) {
        Ok(Some(_)) => {
            warn!(
                stage = "pre_pam_logind_membership",
                worker_already_in_logind_session = true,
                "worker must be launched by the system manager, not from an inherited login session"
            );
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::WorkerAlreadyInLogindSession,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
        Ok(None) => debug!(
            stage = "pre_pam_logind_membership",
            worker_already_in_logind_session = false,
            "worker is not associated with an existing logind session"
        ),
        Err(error) => warn!(
            stage = "pre_pam_logind_membership",
            ?error,
            "could not determine worker logind membership; continuing so PAM/logind remains authoritative"
        ),
    }
    info!(
        source_path = ?launch_plan.source_path,
        executable = ?launch_plan.executable,
        argc = launch_plan.argv.len(),
        "canonical session execution plan accepted"
    );
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
        tty: Some(format!("/dev/tty{}", terminal.lease().vtnr().number())),
    };
    let open_result = catch_unwind(AssertUnwindSafe(|| transaction.open_session(&metadata)));
    let session = StartedSession {
        username: request.username,
        session: request.session,
    };

    match open_result {
        Ok(Ok(())) => {
            let pam_environment = match transaction.session_environment() {
                Ok(environment) => environment,
                Err(error) => {
                    warn!(
                        username = %canonical_username,
                        session = %session.session.id,
                        ?error,
                        "worker failed to extract PAM graphical runtime environment"
                    );
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::RuntimeEnvironmentFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
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
            if pam_environment.session_id != logind.id.as_str() {
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::LogindSessionIdMismatch,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let runtime_dir = PathBuf::from(std::ffi::OsString::from_vec(
                pam_environment.runtime_dir.bytes.clone(),
            ));
            if runtime_dir_validator
                .validate(&runtime_dir, credentials.identity.uid)
                .is_err()
            {
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::RuntimeDirectoryInvalid,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let selinux_exec_context = match selinux_context_manager.capture_pending() {
                Ok(context) => context,
                Err(error) => {
                    warn!(
                        stage = "capture_pam_selinux_exec_context",
                        ?error,
                        "worker could not capture the PAM SELinux exec context"
                    );
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
            if selinux_exec_context.is_some() && selinux_context_manager.clear_pending().is_err() {
                warn!(
                    stage = "clear_pam_selinux_exec_context",
                    "worker could not clear the pending PAM SELinux exec context"
                );
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
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
            debug!(
                stage = "before_child_spawn",
                pam_selinux_exec_context_present = selinux_exec_context.is_some(),
                "prepared SELinux exec-context handoff for session child"
            );
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
                    session_class: "user".to_owned(),
                    session_desktop: session.session.id.clone(),
                    session_id: logind.id.as_str().to_owned(),
                    runtime_dir: SessionChildUnixPath {
                        bytes: pam_environment.runtime_dir.bytes,
                    },
                    seat: terminal.lease().seat().as_str().to_owned(),
                    vtnr: terminal.lease().vtnr().number(),
                    dbus_session_bus_address: None,
                    imported_locale: pam_environment.imported_locale,
                    selinux_exec_context: selinux_exec_context.clone(),
                    probe_path,
                    exec_plan: launch_plan,
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
            // The explicit graphical watchdog protects the launch proof only.
            // Once Started is emitted, the session may legitimately live for
            // hours or days and is governed by process supervision instead.
            let launch_watchdog_deadline = Instant::now() + watchdog;
            let pending_handoff = match child_runner.run_child_until_ready(
                SessionChildExpectation {
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
                },
            ) {
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
            let child_report = pending_handoff.report().clone();
            launch_phase_gate.reached(WorkerLaunchPhase::PendingHandoffBeforeScope)?;
            if let Some(signal) = pending_worker_signal()? {
                emit_fixture_launch_signal(signal);
                info!("worker signal received during PendingExecHandoff; cancelling launch");
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            if Instant::now() >= launch_watchdog_deadline {
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            if !valid_terminal_proof(
                &child_report,
                terminal.lease().seat().as_str(),
                terminal.lease().vtnr().number(),
            ) {
                let _ = pending_handoff.abort();
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
                    let _ = pending_handoff.abort();
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
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            // The post-exec probe remains blocked until its dedicated systemd
            // scope is created, independently re-resolved, and registered.
            if Instant::now() >= launch_watchdog_deadline {
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let requires_registration = payload_scope_manager.requires_supervisor_registration();
            if requires_registration && control_listener.is_none() {
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let logind_session_id =
                niralis_session::LogindSessionId::new(logind.id.as_str().to_owned())
                    .ok_or(SessionError::AuthenticatedSessionFailed)?;
            let mut authoritative_scope = match payload_scope_manager.prepare(
                pending_handoff.report(),
                pending_handoff.authoritative_pidfd(),
                credentials.identity.uid,
                &logind_session_id,
                std::process::id(),
                launcher_pid,
                launch_watchdog_deadline,
            ) {
                Ok(scope) => scope,
                Err(error) => {
                    warn!(
                        ?error,
                        "authoritative payload scope preparation failed before CommitExec"
                    );
                    let _ = pending_handoff.abort();
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
            let registration_nonce = authoritative_scope.identity().invocation_id.clone();
            if requires_registration {
                if let Err(error) = write_envelope(
                    writer,
                    WorkerResponse::PayloadScopePrepared {
                        worker_id: worker_id.clone(),
                        expected_worker_pid: std::process::id(),
                        session_pid: pending_handoff.report().child_pid,
                        registration_nonce: registration_nonce.clone(),
                        scope_identity: authoritative_scope.identity().clone(),
                    },
                ) {
                    let _ = pending_handoff.abort();
                    if let Err(cleanup_error) =
                        authoritative_scope.cleanup(launch_watchdog_deadline)
                    {
                        warn!(
                            ?cleanup_error,
                            "payload scope cleanup after registration transport failure failed"
                        );
                    }
                    drop(transaction);
                    return Err(error);
                }
                emit_fixture_event("PayloadScopePreparedSent");
                info!(unit = %authoritative_scope.identity().unit_name, "payload scope prepared for supervisor registration");
                launch_phase_gate.reached(WorkerLaunchPhase::ScopePinnedBeforeAck)?;
                if let Err(error) = await_payload_scope_ack(
                    &worker_id,
                    std::process::id(),
                    &registration_nonce,
                    launch_watchdog_deadline,
                ) {
                    warn!(?error, "payload scope registration acknowledgement failed");
                    let scope_identity = authoritative_scope.identity().clone();
                    let probe_reaped = pending_handoff.abort().is_ok();
                    let local_cleanup_succeeded = probe_reaped
                        && authoritative_scope
                            .cleanup_preserving_pin(launch_watchdog_deadline)
                            .is_ok();
                    if !local_cleanup_succeeded {
                        warn!(probe_reaped, "payload scope pre-commit cleanup failed");
                    }
                    let release = request_payload_scope_release(
                        writer,
                        &worker_id,
                        &registration_nonce,
                        &scope_identity,
                        local_cleanup_succeeded,
                        launch_watchdog_deadline,
                    );
                    match release {
                        Ok(PayloadScopeReleaseOutcome::Released) => {
                            emit_fixture_event("PayloadScopeReleasedReceived");
                            if authoritative_scope.release_pin().is_err() {
                                wait_for_prestarted_recovery(
                                    authoritative_scope,
                                    transaction,
                                    terminal,
                                );
                            }
                        }
                        Ok(PayloadScopeReleaseOutcome::RecoveryRequired) | Err(_) => {
                            emit_fixture_event("PayloadScopeRecoveryRequiredReceived");
                            wait_for_prestarted_recovery(
                                authoritative_scope,
                                transaction,
                                terminal,
                            );
                        }
                    }
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
                    "authenticated payload scope registration acknowledged; CommitExec authorized"
                );
                emit_fixture_event("PayloadScopeAcknowledged");
                launch_phase_gate.reached(WorkerLaunchPhase::AckReceivedBeforeCommitExec)?;
            }
            if let Some(signal) = pending_worker_signal()? {
                emit_fixture_launch_signal(signal);
                info!("worker signal received during PendingExecHandoff; CommitExec cancelled");
                let scope_identity = authoritative_scope.identity().clone();
                let probe_reaped = pending_handoff.abort().is_ok();
                let local_cleanup_succeeded = probe_reaped
                    && authoritative_scope
                        .cleanup_preserving_pin(launch_watchdog_deadline)
                        .is_ok();
                if requires_registration {
                    let release = request_payload_scope_release(
                        writer,
                        &worker_id,
                        &registration_nonce,
                        &scope_identity,
                        local_cleanup_succeeded,
                        launch_watchdog_deadline,
                    );
                    match release {
                        Ok(PayloadScopeReleaseOutcome::Released) => {
                            emit_fixture_event("PayloadScopeReleasedReceived");
                            if authoritative_scope.release_pin().is_err() {
                                wait_for_prestarted_recovery(
                                    authoritative_scope,
                                    transaction,
                                    terminal,
                                );
                            }
                        }
                        Ok(PayloadScopeReleaseOutcome::RecoveryRequired) | Err(_) => {
                            emit_fixture_event("PayloadScopeRecoveryRequiredReceived");
                            wait_for_prestarted_recovery(
                                authoritative_scope,
                                transaction,
                                terminal,
                            );
                        }
                    }
                } else if authoritative_scope.release_pin().is_err() {
                    wait_for_prestarted_recovery(authoritative_scope, transaction, terminal);
                }
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let child_report = match pending_handoff.commit_exec() {
                Ok(report) => report,
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker failed to commit the post-exec session handoff");
                    let scope_identity = authoritative_scope.identity().clone();
                    let local_cleanup_succeeded = authoritative_scope
                        .cleanup(launch_watchdog_deadline)
                        .is_ok();
                    if !local_cleanup_succeeded {
                        warn!("payload scope cleanup after CommitExec failure failed");
                    }
                    if requires_registration {
                        let _ = request_payload_scope_release(
                            writer,
                            &worker_id,
                            &registration_nonce,
                            &scope_identity,
                            local_cleanup_succeeded,
                            launch_watchdog_deadline,
                        );
                    }
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::CommitFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            // The probe deliberately remains in niralis_t while it is blocked.
            // It applies the PAM-provided pending exec context only after
            // CommitExec, immediately before execve(2). Therefore the context
            // proof belongs here, after the status pipe has proved that final
            // exec succeeded, but before Started can be emitted.
            if let Some(expected_context) = &selinux_exec_context {
                let context_error = match selinux_context_manager
                    .context_for_pid(child_report.child_pid)
                {
                    Ok(observed_context) if expected_context.matches(&observed_context) => None,
                    Ok(observed_context) => {
                        warn!(
                            stage = "post_exec_selinux_context",
                            pid = child_report.child_pid,
                            expected_context = %expected_context.as_str(),
                            observed_context = %observed_context.as_str(),
                            "final session process SELinux context did not match the PAM context"
                        );
                        Some(())
                    }
                    Err(error) => {
                        warn!(
                            stage = "post_exec_selinux_context",
                            pid = child_report.child_pid,
                            ?error,
                            "could not read the final session process SELinux context"
                        );
                        Some(())
                    }
                };
                if context_error.is_some() {
                    let scope_identity = authoritative_scope.identity().clone();
                    if let Err(error) = child_runner.terminate(SESSION_TERMINATION_GRACE) {
                        warn!(?error, "final session process cleanup after SELinux context verification failure failed");
                    }
                    let local_cleanup_succeeded = authoritative_scope
                        .cleanup(launch_watchdog_deadline)
                        .is_ok();
                    if !local_cleanup_succeeded {
                        warn!("payload scope cleanup after SELinux context verification failure failed");
                    }
                    if requires_registration {
                        let _ = request_payload_scope_release(
                            writer,
                            &worker_id,
                            &registration_nonce,
                            &scope_identity,
                            local_cleanup_succeeded,
                            launch_watchdog_deadline,
                        );
                    }
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::SessionChildFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            }
            // Ownership of the validated boundary remains live for the entire
            // Running state. A3.2 will use it for bounded scope termination.
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
            emit_fixture_event("Running");
            info!(username = %canonical_username, session = %session.session.id, pid = child_report.child_pid, "worker session started; PAM transaction remains open");
            let child_status = match wait_for_session(
                control_listener,
                child_runner.as_ref(),
                worker_id,
                child_report.child_pid,
                child_report.process_identity.pgid,
                authoritative_scope.as_ref(),
            ) {
                Ok(SessionWaitResult::Legacy(status)) => status,
                Ok(SessionWaitResult::Graceful(outcome)) => {
                    info!(?outcome, "graceful outcome received");
                    match crate::termination::consume_graceful_outcome(
                        outcome,
                        authoritative_scope.as_ref(),
                    ) {
                        crate::termination::GracefulFinalizationDecision::FinalizeCooperative(
                            proof,
                        ) => {
                            emit_fixture_event("BoundaryEmptyProofAccepted");
                            return finalize_cooperative_session(
                                authoritative_scope.as_mut(),
                                transaction,
                                &mut terminal,
                                proof,
                            );
                        }
                        decision => {
                            match &decision {
                                crate::termination::GracefulFinalizationDecision::NeedsEscalation { .. } => {
                                    emit_fixture_event("NeedsEscalation");
                                    emit_fixture_event("OwnershipRetained:Pam,Vt,Pin");
                                }
                                crate::termination::GracefulFinalizationDecision::RecoveryRequired { .. } => {
                                    emit_fixture_event("RecoveryRequired");
                                    emit_fixture_event("OwnershipRetained:Pam,Vt,Pin");
                                }
                                crate::termination::GracefulFinalizationDecision::FinalizeCooperative(_) => unreachable!(),
                            }
                            warn!(?decision, "graceful finalization requires escalation or recovery; PAM, VT and pin remain owned");
                            wait_for_graceful_handoff();
                        }
                    }
                }
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
    listener: Option<UnixListener>,
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

fn wait_for_session_with_grace(
    listener: Option<UnixListener>,
    child_runner: &dyn crate::session_child::SessionChildRunner,
    worker_id: String,
    session_pid: u32,
    session_pgid: u32,
    authoritative_scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
    grace: Duration,
    expected_control_uid: u32,
) -> Result<SessionWaitResult, SessionError> {
    use crate::termination::{
        BoundaryTerminalObservation, GracefulTerminationCoordinator, GracefulTerminationError,
        LeaderExit, TerminationCause, WorkerTerminationSignal,
    };
    let mut coordinator = match GracefulTerminationCoordinator::new() {
        Ok(coordinator) => coordinator,
        Err(_) => {
            return Ok(SessionWaitResult::Graceful(
                crate::termination::GracefulTerminationOutcome::InfrastructureFailure {
                    cause: TerminationCause::RuntimeFailure,
                    leader_exit: None,
                    error: GracefulTerminationError::Timer,
                },
            ))
        }
    };
    let timer_flags = unsafe { libc::fcntl(coordinator.timer_fd(), libc::F_GETFD) };
    if timer_flags >= 0 && timer_flags & libc::FD_CLOEXEC != 0 {
        emit_fixture_event("TimerFdCloexec");
    }
    let signal_fd = worker_signal_fd();
    let supervisor_fd = supervisor_channel_fd();
    if signal_fd < 0 {
        return wait_for_session_without_signal_fd(
            listener,
            child_runner,
            worker_id,
            session_pid,
            session_pgid,
        )
        .map(SessionWaitResult::Legacy);
    }
    let pidfd = child_runner.authoritative_pidfd();
    if pidfd < 0 {
        return Ok(SessionWaitResult::Graceful(
            coordinator.infrastructure(GracefulTerminationError::LeaderReap),
        ));
    }
    let mut leader_reaped = false;
    let mut observer: Option<Box<dyn crate::payload_scope::PayloadBoundaryObserver>> = None;
    loop {
        let mut fds = [
            libc::pollfd {
                fd: if leader_reaped { -1 } else { pidfd },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: listener.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signal_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: coordinator.timer_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: supervisor_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: observer.as_ref().map_or(-1, |value| value.as_raw_fd()),
                events: observer.as_ref().map_or(0, |value| value.poll_events()),
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Ok(SessionWaitResult::Graceful(
                coordinator.infrastructure(GracefulTerminationError::Poll),
            ));
        }
        let mut trigger = None;
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 && !leader_reaped {
            let status = match child_runner.poll_child() {
                Ok(status) => status,
                Err(_) => {
                    return Ok(SessionWaitResult::Graceful(
                        coordinator.infrastructure(GracefulTerminationError::LeaderReap),
                    ))
                }
            };
            if let Some(status) = status {
                let exit = LeaderExit::from_status(status);
                info!(?exit, "authoritative session leader exited");
                coordinator.record_leader_exit(exit.clone());
                leader_reaped = true;
                trigger = Some(TerminationCause::LeaderExited(exit));
            }
        }
        if fds[5].revents != 0 {
            let Some(boundary_observer) = observer.as_mut() else {
                return Ok(SessionWaitResult::Graceful(
                    coordinator.infrastructure(GracefulTerminationError::BoundaryObserver),
                ));
            };
            if boundary_observer.consume_wakeup().is_err() {
                return Ok(SessionWaitResult::Graceful(
                    coordinator.infrastructure(GracefulTerminationError::BoundaryObserver),
                ));
            }
            match authoritative_scope.boundary_appears_terminal() {
                Ok(true) => {
                    emit_fixture_event("BoundaryCandidate");
                    return Ok(SessionWaitResult::Graceful(coordinator.boundary_candidate(
                        BoundaryTerminalObservation::CgroupEventRevalidated,
                    )));
                }
                Ok(false) => {}
                Err(error) => {
                    return Ok(SessionWaitResult::Graceful(coordinator.scope_error(error)))
                }
            }
        }
        if fds[2].revents & libc::POLLIN != 0 {
            loop {
                let signal = match crate::termination::read_signal_fd(signal_fd) {
                    Ok(Some(signal)) => signal,
                    Ok(None) => break,
                    Err(_) => {
                        return Ok(SessionWaitResult::Graceful(
                            coordinator.infrastructure(GracefulTerminationError::Signal),
                        ))
                    }
                };
                let name = match signal {
                    libc::SIGTERM => "SIGTERM",
                    libc::SIGINT => "SIGINT",
                    libc::SIGHUP => "SIGHUP",
                    _ => "UNKNOWN",
                };
                info!(signal = name, "worker signal received");
                let Some(signal) = WorkerTerminationSignal::from_raw(signal) else {
                    return Ok(SessionWaitResult::Graceful(
                        coordinator.infrastructure(GracefulTerminationError::Signal),
                    ));
                };
                trigger.get_or_insert(TerminationCause::WorkerSignal(signal));
            }
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            warn!("control channel disconnected; terminating session");
            trigger.get_or_insert(TerminationCause::SupervisorDisconnected);
        }
        if fds[4].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            warn!("supervisor channel disconnected; terminating session");
            trigger.get_or_insert(TerminationCause::SupervisorDisconnected);
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let Some(listener) = listener.as_ref() else {
                return Ok(SessionWaitResult::Graceful(
                    coordinator.infrastructure(GracefulTerminationError::Control),
                ));
            };
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if !peer_has_uid(&stream, expected_control_uid) {
                        continue;
                    }
                    let request = match read_control_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => {
                            return Ok(SessionWaitResult::Graceful(
                                coordinator.infrastructure(GracefulTerminationError::Control),
                            ))
                        }
                    };
                    if request.version != WORKER_CONTROL_PROTOCOL_VERSION {
                        return Ok(SessionWaitResult::Graceful(
                            coordinator.infrastructure(GracefulTerminationError::Control),
                        ));
                    }
                    match request.message {
                        WorkerControlRequest::PayloadScopeRegistered { .. } => {
                            return Ok(SessionWaitResult::Graceful(
                                coordinator.infrastructure(GracefulTerminationError::Control),
                            ));
                        }
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
                            trigger.get_or_insert(TerminationCause::InternalTerminateRequest);
                        }
                        _ => {
                            return Ok(SessionWaitResult::Graceful(
                                coordinator.infrastructure(GracefulTerminationError::Control),
                            ))
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    return Ok(SessionWaitResult::Graceful(
                        coordinator.infrastructure(GracefulTerminationError::Control),
                    ))
                }
            }
        }
        if let Some(new_cause) = trigger {
            if let Some(original) = coordinator.cause() {
                info!(original_cause = ?original, new_cause = ?new_cause, "duplicate termination trigger ignored");
            } else {
                info!(cause = ?new_cause, "session termination requested");
                emit_fixture_cause(&new_cause);
                if let TerminationCause::WorkerSignal(signal) = &new_cause {
                    debug!(
                        ?signal,
                        "worker signal selected as authoritative termination cause"
                    );
                }
                match coordinator.begin(new_cause, grace, authoritative_scope) {
                    Ok(Some(new_observer)) => observer = Some(new_observer),
                    Ok(None) => {}
                    Err(outcome) => return Ok(SessionWaitResult::Graceful(outcome)),
                }
                emit_fixture_event("TimerArmed");
                info!(unit = %authoritative_scope.identity().unit_name, invocation_id = %authoritative_scope.identity().invocation_id, "graceful payload scope termination requested");
                info!(duration_ms = grace.as_millis(), "grace period armed");
            }
        }
        let deadline_expired = if fds[3].revents & libc::POLLIN != 0 {
            match coordinator.consume_deadline() {
                Ok(expired) => expired,
                Err(_) => {
                    return Ok(SessionWaitResult::Graceful(
                        coordinator.infrastructure(GracefulTerminationError::Timer),
                    ))
                }
            }
        } else {
            false
        };
        if deadline_expired {
            warn!("grace deadline expired");
            emit_fixture_event("DeadlineExpired");
            return Ok(SessionWaitResult::Graceful(coordinator.deadline_expired()));
        }
    }
}

enum SessionWaitResult {
    Legacy(std::process::ExitStatus),
    Graceful(crate::termination::GracefulTerminationOutcome),
}

fn finalize_cooperative_session(
    scope: &mut dyn crate::payload_scope::AuthoritativePayloadScope,
    mut transaction: Box<dyn niralis_auth::AuthenticatedTransaction>,
    terminal: &mut VirtualTerminalGuard,
    proof: crate::termination::BoundaryEmptyProof,
) -> Result<(), SessionError> {
    info!("releasing pinned systemd unit reference");
    if let Err(error) = scope.release_pin() {
        warn!(
            ?error,
            "pinned unit reference release failed after empty proof"
        );
    }
    info!("closing worker PAM transaction after empty proof");
    let pam_result = transaction.close_session().map_err(|error| {
        warn!(?error, "worker PAM close failed after empty proof");
        SessionError::AuthenticatedSessionFailed
    });
    drop(transaction);
    info!("releasing session VT after PAM close");
    let vt_result = terminal.release().map_err(|error| {
        warn!(?error, "session VT release failed after PAM close");
        SessionError::AuthenticatedSessionFailed
    });
    pam_result?;
    vt_result?;
    info!("cooperative session finalization complete");
    emit_fixture_event("WorkerReturning");
    if matches!(
        proof.leader_exit(),
        crate::termination::LeaderExit::ExitedZero
    ) {
        Ok(())
    } else {
        Err(SessionError::AuthenticatedSessionFailed)
    }
}

fn wait_for_graceful_handoff() -> ! {
    let mut fd = libc::pollfd {
        fd: worker_signal_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        fd.revents = 0;
        let _ = unsafe { libc::poll(&mut fd, 1, -1) };
        while crate::termination::read_signal_fd(fd.fd)
            .ok()
            .flatten()
            .is_some()
        {}
    }
}

fn wait_for_prestarted_recovery(
    _scope: Box<dyn crate::payload_scope::AuthoritativePayloadScope>,
    _transaction: Box<dyn niralis_auth::AuthenticatedTransaction>,
    _terminal: VirtualTerminalGuard,
) -> ! {
    emit_fixture_event("PreStartedRecoveryHeld");
    wait_for_graceful_handoff()
}

fn wait_for_session_without_signal_fd(
    listener: Option<UnixListener>,
    child_runner: &dyn crate::session_child::SessionChildRunner,
    worker_id: String,
    session_pid: u32,
    session_pgid: u32,
) -> Result<std::process::ExitStatus, SessionError> {
    // Test-only/backward-compatible seam for dependency-injected unit tests.
    // The production entrypoint always installs WORKER_SIGNAL_FD and therefore
    // cannot enter this PGID-based legacy path while Running.
    loop {
        match child_runner
            .wait_for_child_or_control(listener.as_ref().map(AsRawFd::as_raw_fd))
            .map_err(|_| SessionError::AuthenticatedSessionFailed)?
        {
            crate::session_child::SessionChildWaitEvent::Exited(status) => return Ok(status),
            crate::session_child::SessionChildWaitEvent::ControlReady => {
                let listener = listener
                    .as_ref()
                    .ok_or(SessionError::AuthenticatedSessionFailed)?;
                match listener.accept() {
                    Ok((mut stream, _)) if peer_is_root(&stream) => {
                        let request = read_control_request(&mut stream)
                            .map_err(|_| SessionError::AuthenticatedSessionFailed)?;
                        match request.message {
                            WorkerControlRequest::Terminate {
                                worker_id: requested_worker_id,
                                expected_worker_pid,
                                expected_session_pid,
                                expected_session_pgid,
                            } if request.version == WORKER_CONTROL_PROTOCOL_VERSION
                                && requested_worker_id == worker_id
                                && expected_worker_pid == std::process::id()
                                && expected_session_pid == session_pid
                                && expected_session_pgid == session_pgid =>
                            {
                                return child_runner
                                    .terminate(SESSION_TERMINATION_GRACE)
                                    .map_err(|_| SessionError::AuthenticatedSessionFailed);
                            }
                            _ => return Err(SessionError::AuthenticatedSessionFailed),
                        }
                    }
                    Ok(_) => {}
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(SessionError::AuthenticatedSessionFailed),
                }
            }
        }
    }
}

fn peer_is_root(stream: &UnixStream) -> bool {
    peer_has_uid(stream, 0)
}

fn peer_has_uid(stream: &UnixStream, expected_uid: u32) -> bool {
    peer_credentials(stream).is_some_and(|credentials| credentials.uid == expected_uid)
}

#[cfg(test)]
mod graceful_coordinator_tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
        Arc, Mutex,
    };

    static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct OrderedTransaction {
        events: Arc<Mutex<Vec<&'static str>>>,
        close_fails: bool,
    }
    impl niralis_auth::AuthenticatedTransaction for OrderedTransaction {
        fn user(&self) -> &niralis_auth::AuthenticatedUser {
            panic!("unused by finalizer")
        }
        fn open_session(
            &mut self,
            _: &niralis_auth::PamSessionMetadata,
        ) -> Result<(), niralis_auth::AuthSessionError> {
            panic!("unused by finalizer")
        }
        fn session_environment(
            &mut self,
        ) -> Result<niralis_auth::PamSessionEnvironment, niralis_auth::AuthSessionError> {
            panic!("unused by finalizer")
        }
        fn close_session(&mut self) -> Result<(), niralis_auth::AuthSessionError> {
            self.events.lock().unwrap().push("pam_close_started");
            if self.close_fails {
                Err(niralis_auth::AuthSessionError::CloseFailed)
            } else {
                self.events.lock().unwrap().push("pam_close_completed");
                Ok(())
            }
        }
    }
    impl Drop for OrderedTransaction {
        fn drop(&mut self) {
            self.events.lock().unwrap().push("pam_dropped");
        }
    }

    struct OrderedLease {
        events: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }
    impl crate::VirtualTerminalLease for OrderedLease {
        fn seat(&self) -> &niralis_auth::SeatId {
            panic!("unused by finalizer")
        }
        fn vtnr(&self) -> niralis_auth::VirtualTerminalId {
            niralis_auth::VirtualTerminalId::new(1).unwrap()
        }
        fn duplicate_terminal_fd(&self) -> Result<OwnedFd, crate::VirtualTerminalError> {
            panic!("unused by finalizer")
        }
        fn activate(&mut self, _: Duration) -> Result<(), crate::VirtualTerminalError> {
            panic!("unused by finalizer")
        }
        fn release(&mut self) -> Result<(), crate::VirtualTerminalError> {
            self.events.lock().unwrap().push("vt_released");
            if self.fail {
                Err(crate::VirtualTerminalError::CleanupFailed)
            } else {
                Ok(())
            }
        }
    }

    struct OrderedScope {
        identity: niralis_session::PayloadScopeIdentity,
        events: Arc<Mutex<Vec<&'static str>>>,
        unref_fails: bool,
    }
    impl crate::payload_scope::AuthoritativePayloadScope for OrderedScope {
        fn identity(&self) -> &niralis_session::PayloadScopeIdentity {
            &self.identity
        }
        fn control_group(&self) -> &str {
            "/test"
        }
        fn cleanup(
            self: Box<Self>,
            _: Instant,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            Ok(())
        }
        fn release_pin(&mut self) -> Result<(), crate::payload_scope::PayloadScopeError> {
            self.events.lock().unwrap().push("unit_unref_attempted");
            if self.unref_fails {
                Err(crate::payload_scope::PayloadScopeError::UnrefFailed)
            } else {
                Ok(())
            }
        }
    }

    struct EventObserver(OwnedFd);
    impl crate::payload_scope::PayloadBoundaryObserver for EventObserver {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
        fn poll_events(&self) -> libc::c_short {
            libc::POLLIN
        }
        fn consume_wakeup(&mut self) -> Result<(), crate::payload_scope::PayloadScopeError> {
            read_event(self.0.as_raw_fd())
                .then_some(())
                .ok_or(crate::payload_scope::PayloadScopeError::ObserverFailed)
        }
    }

    struct EventScope {
        identity: niralis_session::PayloadScopeIdentity,
        boundary_fd: OwnedFd,
        pid_fd: RawFd,
        cooperative: bool,
        terminal: AtomicBool,
        requests: AtomicUsize,
        unrefs: AtomicUsize,
        fail: Option<crate::payload_scope::PayloadScopeError>,
        observe_fail: Option<crate::payload_scope::PayloadScopeError>,
    }
    impl EventScope {
        fn new(
            pid_fd: RawFd,
            cooperative: bool,
            fail: Option<crate::payload_scope::PayloadScopeError>,
        ) -> Self {
            Self {
                identity: niralis_session::PayloadScopeIdentity {
                    unit_name: "niralis-payload-11111111111111111111111111111111.scope".into(),
                    invocation_id: "11111111111111111111111111111111".into(),
                    expected_uid: 1000,
                    logind_session_id: niralis_session::LogindSessionId::new("1".into()).unwrap(),
                },
                boundary_fd: event_fd(),
                pid_fd,
                cooperative,
                terminal: AtomicBool::new(false),
                requests: AtomicUsize::new(0),
                unrefs: AtomicUsize::new(0),
                fail,
                observe_fail: None,
            }
        }
    }
    impl crate::payload_scope::AuthoritativePayloadScope for EventScope {
        fn identity(&self) -> &niralis_session::PayloadScopeIdentity {
            &self.identity
        }
        fn control_group(&self) -> &str {
            "/test"
        }
        fn cleanup(
            self: Box<Self>,
            _: Instant,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            Ok(())
        }
        fn create_boundary_observer(
            &self,
        ) -> Result<
            Box<dyn crate::payload_scope::PayloadBoundaryObserver>,
            crate::payload_scope::PayloadScopeError,
        > {
            let fd = unsafe { libc::fcntl(self.boundary_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                Err(crate::payload_scope::PayloadScopeError::ObserverFailed)
            } else {
                Ok(Box::new(EventObserver(unsafe { OwnedFd::from_raw_fd(fd) })))
            }
        }
        fn request_graceful_termination(
            &self,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            self.requests.fetch_add(1, AtomicOrdering::SeqCst);
            if let Some(error) = &self.fail {
                return Err(error.clone());
            }
            if self.cooperative {
                self.terminal.store(true, AtomicOrdering::SeqCst);
                write_event(self.pid_fd);
                write_event(self.boundary_fd.as_raw_fd());
            }
            Ok(())
        }
        fn boundary_appears_terminal(
            &self,
        ) -> Result<bool, crate::payload_scope::PayloadScopeError> {
            if let Some(error) = &self.observe_fail {
                Err(error.clone())
            } else {
                Ok(self.terminal.load(AtomicOrdering::SeqCst))
            }
        }
        fn prove_empty_boundary(
            &self,
            leader_exit: &crate::termination::LeaderExit,
        ) -> Result<crate::termination::BoundaryEmptyProof, crate::payload_scope::PayloadScopeError>
        {
            if !self.terminal.load(AtomicOrdering::SeqCst) {
                return Err(crate::payload_scope::PayloadScopeError::BoundaryNotEmpty);
            }
            Ok(crate::termination::BoundaryEmptyProof::new(
                &self.identity,
                self.control_group(),
                leader_exit.clone(),
            ))
        }
        fn release_pin(&mut self) -> Result<(), crate::payload_scope::PayloadScopeError> {
            self.unrefs.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(())
        }
    }

    struct EventRunner {
        pidfd: OwnedFd,
        status: Mutex<Option<std::process::ExitStatus>>,
    }
    impl crate::session_child::SessionChildRunner for EventRunner {
        fn run_child_until_ready(
            &self,
            _: crate::session_child::SessionChildExpectation,
        ) -> Result<
            Box<dyn crate::session_child::PendingExecHandoff>,
            crate::session_child::SessionChildError,
        > {
            Err(crate::session_child::SessionChildError::IoFailed)
        }
        fn authoritative_pidfd(&self) -> RawFd {
            self.pidfd.as_raw_fd()
        }
        fn poll_child(
            &self,
        ) -> Result<Option<std::process::ExitStatus>, crate::session_child::SessionChildError>
        {
            let _ = read_event(self.pidfd.as_raw_fd());
            Ok(self.status.lock().unwrap().take())
        }
    }

    struct OwnedLifecycle(Arc<AtomicUsize>);
    impl Drop for OwnedLifecycle {
        fn drop(&mut self) {
            self.0.fetch_add(1, AtomicOrdering::SeqCst);
        }
    }

    fn event_fd() -> OwnedFd {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    }
    fn write_event(fd: RawFd) {
        let one = 1_u64;
        assert_eq!(
            unsafe { libc::write(fd, (&one as *const u64).cast(), 8) },
            8
        );
    }
    fn read_event(fd: RawFd) -> bool {
        let mut value = 0_u64;
        (unsafe { libc::read(fd, (&mut value as *mut u64).cast(), 8) }) == 8
    }

    fn run_signal_case(signal: i32, expected: crate::termination::WorkerTerminationSignal) {
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        set_supervisor_channel_fd(-1);
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(0))),
        };
        let scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        let drops = Arc::new(AtomicUsize::new(0));
        let pam = OwnedLifecycle(drops.clone());
        let vt = OwnedLifecycle(drops.clone());
        assert_eq!(
            unsafe { libc::pthread_kill(libc::pthread_self(), signal) },
            0
        );
        let result = wait_for_session_with_grace(
            None,
            &runner,
            "worker".into(),
            1,
            1,
            &scope,
            Duration::from_millis(100),
            unsafe { libc::getuid() },
        )
        .unwrap();
        assert!(
            matches!(result, SessionWaitResult::Graceful(crate::termination::GracefulTerminationOutcome::BoundaryTerminalCandidate { cause: crate::termination::TerminationCause::WorkerSignal(value), leader_exit: Some(crate::termination::LeaderExit::ExitedZero), .. }) if value == expected)
        );
        assert_eq!(scope.requests.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(drops.load(AtomicOrdering::SeqCst), 0);
        drop((pam, vt));
        set_worker_signal_fd(-1);
    }

    #[test]
    fn production_loop_cooperates_for_real_worker_signals() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        run_signal_case(
            libc::SIGTERM,
            crate::termination::WorkerTerminationSignal::Sigterm,
        );
        run_signal_case(
            libc::SIGINT,
            crate::termination::WorkerTerminationSignal::Sigint,
        );
        run_signal_case(
            libc::SIGHUP,
            crate::termination::WorkerTerminationSignal::Sighup,
        );
    }

    #[test]
    fn production_loop_deadline_and_infrastructure_retain_ownership() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        for failure in [
            None,
            Some(crate::payload_scope::PayloadScopeError::BusUnavailable),
        ] {
            let runner = EventRunner {
                pidfd: event_fd(),
                status: Mutex::new(None),
            };
            let scope = EventScope::new(runner.pidfd.as_raw_fd(), false, failure.clone());
            let drops = Arc::new(AtomicUsize::new(0));
            let pam = OwnedLifecycle(drops.clone());
            let vt = OwnedLifecycle(drops.clone());
            assert_eq!(
                unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) },
                0
            );
            let result = wait_for_session_with_grace(
                None,
                &runner,
                "worker".into(),
                1,
                1,
                &scope,
                Duration::from_millis(1),
                unsafe { libc::getuid() },
            )
            .unwrap();
            if failure.is_some() {
                assert!(matches!(
                    result,
                    SessionWaitResult::Graceful(
                        crate::termination::GracefulTerminationOutcome::InfrastructureFailure { .. }
                    )
                ));
            } else {
                assert!(matches!(
                    result,
                    SessionWaitResult::Graceful(
                        crate::termination::GracefulTerminationOutcome::DeadlineExpired { .. }
                    )
                ));
            }
            assert_eq!(drops.load(AtomicOrdering::SeqCst), 0);
            drop((pam, vt));
        }
        set_worker_signal_fd(-1);
    }

    #[test]
    fn simultaneous_boundary_and_deadline_prefers_revalidated_candidate() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(42 << 8))),
        };
        let scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
        let result = wait_for_session_with_grace(
            None,
            &runner,
            "worker".into(),
            1,
            1,
            &scope,
            Duration::from_nanos(1),
            unsafe { libc::getuid() },
        )
        .unwrap();
        assert!(matches!(
            result,
            SessionWaitResult::Graceful(
                crate::termination::GracefulTerminationOutcome::BoundaryTerminalCandidate {
                    leader_exit: Some(crate::termination::LeaderExit::ExitedNonZero(42)),
                    ..
                }
            )
        ));
        set_worker_signal_fd(-1);
    }

    #[test]
    fn replacement_during_observation_is_recovery_required() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(libc::SIGSEGV))),
        };
        let mut scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        scope.observe_fail = Some(crate::payload_scope::PayloadScopeError::UnitReplaced);
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
        let result = wait_for_session_with_grace(
            None,
            &runner,
            "worker".into(),
            1,
            1,
            &scope,
            Duration::from_millis(100),
            unsafe { libc::getuid() },
        )
        .unwrap();
        assert!(
            matches!(result, SessionWaitResult::Graceful(crate::termination::GracefulTerminationOutcome::RecoveryRequired { leader_exit: Some(crate::termination::LeaderExit::KilledBySignal(value)), .. }) if value == libc::SIGSEGV)
        );
        set_worker_signal_fd(-1);
    }

    #[test]
    fn simultaneous_supervisor_disconnect_and_signal_is_single_lifecycle() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        let supervisor = event_fd();
        write_event(supervisor.as_raw_fd());
        set_supervisor_channel_fd(supervisor.as_raw_fd());
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(0))),
        };
        let scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
        let result = wait_for_session_with_grace(
            None,
            &runner,
            "worker".into(),
            1,
            1,
            &scope,
            Duration::from_millis(100),
            unsafe { libc::getuid() },
        )
        .unwrap();
        assert!(matches!(
            result,
            SessionWaitResult::Graceful(
                crate::termination::GracefulTerminationOutcome::BoundaryTerminalCandidate {
                    cause: crate::termination::TerminationCause::WorkerSignal(
                        crate::termination::WorkerTerminationSignal::Sigterm
                    ),
                    ..
                }
            )
        ));
        assert_eq!(scope.requests.load(AtomicOrdering::SeqCst), 1);
        set_supervisor_channel_fd(-1);
        set_worker_signal_fd(-1);
    }

    #[test]
    fn authenticated_pidfd_and_terminate_share_one_poll_cycle() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        set_supervisor_channel_fd(-1);
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(0))),
        };
        write_event(runner.pidfd.as_raw_fd());
        let scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        let path = std::env::temp_dir().join(format!("n-a326-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = bind_control_listener(&path).unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        niralis_session::write_control_request(
            &mut stream,
            WorkerControlRequest::Terminate {
                worker_id: "worker".into(),
                expected_worker_pid: std::process::id(),
                expected_session_pid: 1,
                expected_session_pgid: 1,
            },
        )
        .unwrap();
        let result = wait_for_session_with_grace(
            Some(listener),
            &runner,
            "worker".into(),
            1,
            1,
            &scope,
            Duration::from_millis(100),
            unsafe { libc::getuid() },
        )
        .unwrap();
        assert!(matches!(
            result,
            SessionWaitResult::Graceful(
                crate::termination::GracefulTerminationOutcome::BoundaryTerminalCandidate {
                    cause: crate::termination::TerminationCause::LeaderExited(
                        crate::termination::LeaderExit::ExitedZero
                    ),
                    leader_exit: Some(crate::termination::LeaderExit::ExitedZero),
                    ..
                }
            )
        ));
        assert_eq!(scope.requests.load(AtomicOrdering::SeqCst), 1);
        let _ = std::fs::remove_file(path);
        set_worker_signal_fd(-1);
    }

    #[test]
    fn cooperative_finalizer_orders_unref_pam_and_vt() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let identity = niralis_session::PayloadScopeIdentity {
            unit_name: "niralis-payload-00000000000000000000000000000000.scope".into(),
            invocation_id: "00000000000000000000000000000000".into(),
            expected_uid: 1000,
            logind_session_id: niralis_session::LogindSessionId::new("1".into()).unwrap(),
        };
        let proof = crate::termination::BoundaryEmptyProof::new(
            &identity,
            "/test",
            crate::termination::LeaderExit::ExitedZero,
        );
        let mut scope = OrderedScope {
            identity,
            events: events.clone(),
            unref_fails: false,
        };
        let transaction: Box<dyn niralis_auth::AuthenticatedTransaction> =
            Box::new(OrderedTransaction {
                events: events.clone(),
                close_fails: false,
            });
        let mut terminal = VirtualTerminalGuard::new(Box::new(OrderedLease {
            events: events.clone(),
            fail: false,
        }));
        assert!(
            finalize_cooperative_session(&mut scope, transaction, &mut terminal, proof).is_ok()
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "unit_unref_attempted",
                "pam_close_started",
                "pam_close_completed",
                "pam_dropped",
                "vt_released"
            ]
        );
    }

    #[test]
    fn production_loop_candidate_is_consumed_and_cooperative_finalizer_returns() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(0))),
        };
        let mut scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
        let outcome = match wait_for_session_with_grace(
            None,
            &runner,
            "worker".into(),
            1,
            1,
            &scope,
            Duration::from_millis(100),
            unsafe { libc::getuid() },
        )
        .unwrap()
        {
            SessionWaitResult::Graceful(outcome) => outcome,
            SessionWaitResult::Legacy(_) => panic!("expected graceful outcome"),
        };
        let proof = match crate::termination::consume_graceful_outcome(outcome, &scope) {
            crate::termination::GracefulFinalizationDecision::FinalizeCooperative(proof) => proof,
            decision => panic!("unexpected finalization decision: {decision:?}"),
        };
        let events = Arc::new(Mutex::new(Vec::new()));
        let transaction: Box<dyn niralis_auth::AuthenticatedTransaction> =
            Box::new(OrderedTransaction {
                events: events.clone(),
                close_fails: false,
            });
        let mut terminal = VirtualTerminalGuard::new(Box::new(OrderedLease {
            events: events.clone(),
            fail: false,
        }));
        assert!(
            finalize_cooperative_session(&mut scope, transaction, &mut terminal, proof).is_ok()
        );
        assert_eq!(scope.unrefs.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "pam_close_started",
                "pam_close_completed",
                "pam_dropped",
                "vt_released"
            ]
        );
        set_worker_signal_fd(-1);
    }

    #[test]
    fn unref_failure_does_not_keep_pam_or_vt_and_vt_failure_is_reported() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let identity = niralis_session::PayloadScopeIdentity {
            unit_name: "niralis-payload-00000000000000000000000000000000.scope".into(),
            invocation_id: "00000000000000000000000000000000".into(),
            expected_uid: 1000,
            logind_session_id: niralis_session::LogindSessionId::new("1".into()).unwrap(),
        };
        let proof = crate::termination::BoundaryEmptyProof::new(
            &identity,
            "/test",
            crate::termination::LeaderExit::ExitedZero,
        );
        let mut scope = OrderedScope {
            identity,
            events: events.clone(),
            unref_fails: true,
        };
        let transaction: Box<dyn niralis_auth::AuthenticatedTransaction> =
            Box::new(OrderedTransaction {
                events: events.clone(),
                close_fails: false,
            });
        let mut terminal = VirtualTerminalGuard::new(Box::new(OrderedLease {
            events: events.clone(),
            fail: true,
        }));
        assert!(
            finalize_cooperative_session(&mut scope, transaction, &mut terminal, proof).is_err()
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "unit_unref_attempted",
                "pam_close_started",
                "pam_close_completed",
                "pam_dropped",
                "vt_released"
            ]
        );
    }

    #[test]
    fn pam_close_failure_still_releases_vt_and_returns_failure() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let identity = niralis_session::PayloadScopeIdentity {
            unit_name: "niralis-payload-00000000000000000000000000000000.scope".into(),
            invocation_id: "00000000000000000000000000000000".into(),
            expected_uid: 1000,
            logind_session_id: niralis_session::LogindSessionId::new("1".into()).unwrap(),
        };
        let proof = crate::termination::BoundaryEmptyProof::new(
            &identity,
            "/test",
            crate::termination::LeaderExit::ExitedZero,
        );
        let mut scope = OrderedScope {
            identity,
            events: events.clone(),
            unref_fails: false,
        };
        let transaction: Box<dyn niralis_auth::AuthenticatedTransaction> =
            Box::new(OrderedTransaction {
                events: events.clone(),
                close_fails: true,
            });
        let mut terminal = VirtualTerminalGuard::new(Box::new(OrderedLease {
            events: events.clone(),
            fail: false,
        }));
        assert!(
            finalize_cooperative_session(&mut scope, transaction, &mut terminal, proof).is_err()
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "unit_unref_attempted",
                "pam_close_started",
                "pam_dropped",
                "vt_released"
            ]
        );
    }
}

fn peer_credentials(stream: &UnixStream) -> Option<libc::ucred> {
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
    (result == 0).then_some(credentials)
}

/// Waits for the launcher to acknowledge a scope identity it has already
/// persisted. A3.1 calls this between PayloadScopePrepared and CommitExec.
#[cfg_attr(not(test), allow(dead_code))]
fn await_payload_scope_ack(
    worker_id: &str,
    expected_worker_pid: u32,
    registration_nonce: &str,
    deadline: Instant,
) -> Result<(), SessionError> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or(SessionError::WorkerTimedOut)?;
    let signal_fd = worker_signal_fd();
    let supervisor_fd = supervisor_channel_fd();
    let mut pollfds = [
        libc::pollfd {
            fd: signal_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: supervisor_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
    let result = unsafe {
        libc::poll(
            pollfds.as_mut_ptr(),
            pollfds.len() as libc::nfds_t,
            milliseconds,
        )
    };
    if result == 0 {
        return Err(SessionError::WorkerTimedOut);
    }
    if result < 0 {
        return Err(SessionError::WorkerIoFailed);
    }
    if pollfds[0].revents & libc::POLLIN != 0 {
        if let Ok(Some(signal)) = crate::termination::read_signal_fd(signal_fd) {
            emit_fixture_launch_signal(signal);
        }
        return Err(SessionError::AuthenticatedSessionFailed);
    }
    let supervisor_events = pollfds[1].revents;
    if supervisor_events & libc::POLLIN != 0 {
        let mut stream = duplicate_supervisor_channel()?;
        let read_timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|timeout| !timeout.is_zero())
            .ok_or(SessionError::WorkerTimedOut)?;
        stream
            .set_read_timeout(Some(read_timeout))
            .map_err(|_| SessionError::WorkerIoFailed)?;
        match read_control_request(&mut stream) {
            Ok(envelope) if envelope.version == WORKER_CONTROL_PROTOCOL_VERSION => {
                return match envelope.message {
                    WorkerControlRequest::PayloadScopeRegistered {
                        worker_id: ack_worker_id,
                        expected_worker_pid: ack_pid,
                        registration_nonce: ack_nonce,
                    } if ack_worker_id == worker_id
                        && ack_pid == expected_worker_pid
                        && ack_nonce == registration_nonce =>
                    {
                        Ok(())
                    }
                    _ => Err(SessionError::WorkerProtocolFailed),
                };
            }
            Ok(_) => return Err(SessionError::WorkerProtocolFailed),
            Err(error)
                if supervisor_events & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0 =>
            {
                return Err(error)
            }
            Err(_) => {}
        }
    }
    if supervisor_events & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        emit_fixture_event("LaunchSupervisorDisconnected");
        warn!(stage = "ack", "dedicated supervisor channel disconnected");
        return Err(SessionError::AuthenticatedSessionFailed);
    }
    Err(SessionError::WorkerIoFailed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadScopeReleaseOutcome {
    Released,
    RecoveryRequired,
}

#[allow(clippy::too_many_arguments)]
fn request_payload_scope_release<W: Write>(
    writer: &mut W,
    worker_id: &str,
    registration_nonce: &str,
    identity: &niralis_session::PayloadScopeIdentity,
    local_cleanup_succeeded: bool,
    deadline: Instant,
) -> Result<PayloadScopeReleaseOutcome, SessionError> {
    write_envelope(
        writer,
        WorkerResponse::PayloadScopeReleaseReady {
            worker_id: worker_id.to_owned(),
        },
    )?;
    info!(unit = %identity.unit_name, local_cleanup_succeeded, "payload scope release requested after post-ack launch failure");
    let mut stream = duplicate_supervisor_channel()?;
    let release_nonce = random_release_nonce()?;
    niralis_session::write_control_request(
        &mut stream,
        WorkerControlRequest::PayloadScopeReleaseRequested {
            worker_id: worker_id.to_owned(),
            expected_worker_pid: std::process::id(),
            registration_nonce: registration_nonce.to_owned(),
            release_nonce: release_nonce.clone(),
            scope_identity: identity.clone(),
            local_cleanup_succeeded,
        },
    )?;
    emit_fixture_event("PayloadScopeReleaseRequested:count=1");
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or(SessionError::WorkerTimedOut)?;
    let mut pollfd = libc::pollfd {
        fd: supervisor_channel_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe {
        libc::poll(
            &mut pollfd,
            1,
            timeout.as_millis().min(i32::MAX as u128) as i32,
        )
    };
    if result == 0 {
        return Err(SessionError::WorkerTimedOut);
    }
    if result < 0 {
        return Err(SessionError::WorkerIoFailed);
    }
    if pollfd.revents & libc::POLLIN == 0 {
        if pollfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            warn!(
                stage = "release",
                "dedicated supervisor channel disconnected"
            );
        }
        return Err(SessionError::WorkerIoFailed);
    }
    let read_timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|timeout| !timeout.is_zero())
        .ok_or(SessionError::WorkerTimedOut)?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|_| SessionError::WorkerIoFailed)?;
    let response = read_control_request(&mut stream)?;
    if response.version != WORKER_CONTROL_PROTOCOL_VERSION {
        return Err(SessionError::WorkerProtocolFailed);
    }
    match response.message {
        WorkerControlRequest::PayloadScopeReleased {
            worker_id: response_worker_id,
            expected_worker_pid,
            registration_nonce: response_registration_nonce,
            release_nonce: response_release_nonce,
        } if response_worker_id == worker_id
            && expected_worker_pid == std::process::id()
            && response_registration_nonce == registration_nonce
            && response_release_nonce == release_nonce =>
        {
            info!(unit = %identity.unit_name, "payload scope release independently verified and acknowledged");
            Ok(PayloadScopeReleaseOutcome::Released)
        }
        WorkerControlRequest::PayloadScopeRecoveryRequired {
            worker_id: response_worker_id,
            expected_worker_pid,
            registration_nonce: response_registration_nonce,
            release_nonce: response_release_nonce,
            reason,
        } if response_worker_id == worker_id
            && expected_worker_pid == std::process::id()
            && response_registration_nonce == registration_nonce
            && response_release_nonce == release_nonce =>
        {
            warn!(?reason, unit = %identity.unit_name, "supervisor could not prove payload scope cleanup; recovery required");
            Ok(PayloadScopeReleaseOutcome::RecoveryRequired)
        }
        _ => Err(SessionError::WorkerProtocolFailed),
    }
}

fn random_release_nonce() -> Result<String, SessionError> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| SessionError::WorkerIoFailed)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod pre_started_ack_tests {
    use super::*;

    #[test]
    fn correlated_ack_round_trips_before_started() {
        let (mut launcher, worker) = UnixStream::pair().unwrap();
        let previous = set_supervisor_channel_fd(worker.as_raw_fd());
        let writer = std::thread::spawn(move || {
            niralis_session::write_control_request(
                &mut launcher,
                WorkerControlRequest::PayloadScopeRegistered {
                    worker_id: "worker-test".into(),
                    expected_worker_pid: 42,
                    registration_nonce: "nonce-test".into(),
                },
            )
            .unwrap();
        });
        await_payload_scope_ack(
            "worker-test",
            42,
            "nonce-test",
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        writer.join().unwrap();
        set_supervisor_channel_fd(previous);
    }

    #[test]
    fn divergent_ack_is_rejected() {
        let (mut launcher, worker) = UnixStream::pair().unwrap();
        let previous = set_supervisor_channel_fd(worker.as_raw_fd());
        let writer = std::thread::spawn(move || {
            niralis_session::write_control_request(
                &mut launcher,
                WorkerControlRequest::PayloadScopeRegistered {
                    worker_id: "other-worker".into(),
                    expected_worker_pid: 42,
                    registration_nonce: "nonce-test".into(),
                },
            )
            .unwrap();
        });
        assert_eq!(
            await_payload_scope_ack(
                "worker-test",
                42,
                "nonce-test",
                Instant::now() + Duration::from_secs(1)
            ),
            Err(SessionError::WorkerProtocolFailed)
        );
        writer.join().unwrap();
        set_supervisor_channel_fd(previous);
    }

    #[test]
    fn complete_ack_is_drained_before_hup_is_classified() {
        let (mut launcher, worker) = UnixStream::pair().unwrap();
        let previous = set_supervisor_channel_fd(worker.as_raw_fd());
        niralis_session::write_control_request(
            &mut launcher,
            WorkerControlRequest::PayloadScopeRegistered {
                worker_id: "worker-test".into(),
                expected_worker_pid: 42,
                registration_nonce: "nonce-test".into(),
            },
        )
        .unwrap();
        drop(launcher);
        assert_eq!(
            await_payload_scope_ack(
                "worker-test",
                42,
                "nonce-test",
                Instant::now() + Duration::from_secs(1)
            ),
            Ok(())
        );
        set_supervisor_channel_fd(previous);
    }
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

#[cfg(test)]
mod runtime_dir_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("niralis-4gc-{name}-{}", std::process::id()))
    }

    #[test]
    fn validates_existing_owned_mode_0700_directory() {
        let directory = path("valid");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(LinuxRuntimeDirValidator.validate(&directory, uid).is_ok());
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn rejects_relative_and_symlink_runtime_paths() {
        let directory = path("target");
        let link = path("link");
        let _ = std::fs::remove_dir_all(&directory);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir(&directory).unwrap();
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            LinuxRuntimeDirValidator.validate(Path::new("relative"), uid),
            Err(RuntimeDirValidationError::InvalidPath)
        );
        assert_eq!(
            LinuxRuntimeDirValidator.validate(&link, uid),
            Err(RuntimeDirValidationError::InvalidMetadata)
        );
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
