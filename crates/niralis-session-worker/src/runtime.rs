use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

pub struct WorkerDependencies<'a, F, I, G, C, L> {
    pub authenticator_factory: &'a F,
    pub identity_resolver: &'a I,
    pub supplementary_groups_resolver: &'a G,
    pub session_child_runner_factory: &'a C,
    pub logind_resolver: &'a L,
    pub virtual_terminal_allocator: &'a dyn VirtualTerminalAllocator,
    pub runtime_dir_validator: &'a dyn RuntimeDirValidator,
    pub selinux_context_manager: &'a dyn SelinuxContextManager,
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
            launch_plan,
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
            dependencies.runtime_dir_validator,
            dependencies.selinux_context_manager,
            launch_plan,
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
    runtime_dir_validator: &dyn RuntimeDirValidator,
    selinux_context_manager: &dyn SelinuxContextManager,
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
    let watchdog = match authorize_real_graphical_smoke_for_runtime(&request.session.id) {
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
            if Instant::now() >= launch_watchdog_deadline {
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
            if let Some(expected_context) = &selinux_exec_context {
                match selinux_context_manager.context_for_pid(child_report.child_pid) {
                    Ok(observed_context) if expected_context.matches(&observed_context) => {}
                    Ok(observed_context) => {
                        warn!(
                            stage = "post_exec_selinux_context",
                            pid = child_report.child_pid,
                            expected_context = %expected_context.as_str(),
                            observed_context = %observed_context.as_str(),
                            "final session process SELinux context did not match the PAM context"
                        );
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
                    Err(error) => {
                        warn!(
                            stage = "post_exec_selinux_context",
                            pid = child_report.child_pid,
                            ?error,
                            "could not read the final session process SELinux context"
                        );
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
                }
            }
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
        match child_runner
            .wait_for_child_or_control(listener.as_ref().map(std::os::fd::AsRawFd::as_raw_fd))
            .map_err(|_| SessionError::AuthenticatedSessionFailed)?
        {
            crate::session_child::SessionChildWaitEvent::Exited(status) => return Ok(status),
            crate::session_child::SessionChildWaitEvent::ControlReady => {
                let Some(listener) = listener.as_ref() else {
                    return Err(SessionError::AuthenticatedSessionFailed);
                };
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
            }
        }
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
