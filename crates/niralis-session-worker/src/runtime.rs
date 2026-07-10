use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use niralis_auth::{AuthError, Authenticator, PamAuthenticator};
use niralis_session::{
    read_envelope, write_envelope, SessionError, StartedSession, WorkerErrorCode, WorkerRequest,
    WorkerResponse, WorkerSessionFailureCode,
};
use tracing::{debug, info, warn};

use crate::identity::{
    NssSupplementaryGroupsResolver, NssUnixIdentityResolver, ResolvedUnixCredentials,
    SupplementaryGroupsResolver, UnixIdentityResolver,
};
use crate::privilege_drop::PrivilegeDropTarget;
use crate::session_child::{
    ProcessSessionChildRunnerFactory, SessionChildExpectation, SessionChildRunnerFactory,
};

pub trait WorkerAuthenticatorFactory: Send + Sync {
    fn build(&self, pam_service: &str) -> Box<dyn Authenticator>;
}

pub struct WorkerDependencies<'a, F, I, G, C> {
    pub authenticator_factory: &'a F,
    pub identity_resolver: &'a I,
    pub supplementary_groups_resolver: &'a G,
    pub session_child_runner_factory: &'a C,
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
>(
    reader: &mut R,
    writer: &mut W,
    dependencies: WorkerDependencies<'_, F, I, G, C>,
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
        } => run_pam_session(
            writer,
            dependencies.authenticator_factory,
            dependencies.identity_resolver,
            dependencies.supplementary_groups_resolver,
            dependencies.session_child_runner_factory,
            request,
            pam_service,
            password,
            session_child_path,
        ),
    }
}

fn run_pam_session<
    W: Write,
    F: WorkerAuthenticatorFactory,
    I: UnixIdentityResolver,
    G: SupplementaryGroupsResolver,
    C: SessionChildRunnerFactory,
>(
    writer: &mut W,
    factory: &F,
    identity_resolver: &I,
    supplementary_groups_resolver: &G,
    session_child_runner_factory: &C,
    request: niralis_session::SessionRequest,
    pam_service: String,
    password: niralis_session::WorkerSecret,
    session_child_path: std::path::PathBuf,
) -> Result<(), SessionError> {
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

    let open_result = catch_unwind(AssertUnwindSafe(|| transaction.open_session()));
    let session = StartedSession {
        username: request.username,
        session: request.session,
    };

    match open_result {
        Ok(Ok(())) => {
            info!(username = %canonical_username, session = %session.session.id, "worker PAM session opened");
            let child_runner = match session_child_runner_factory
                .build(Path::new(&session_child_path))
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
            let child_report = match child_runner.run_child(SessionChildExpectation {
                canonical_username: canonical_username.clone(),
                session_id: session.session.id.clone(),
                target_credentials: PrivilegeDropTarget::from(&credentials),
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
            info!(
                username = %canonical_username,
                session = %session.session.id,
                pid = child_report.child_pid,
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
                "worker session child verified post-drop isolation"
            );
            drop(transaction);
            info!(username = %canonical_username, session = %session.session.id, "worker PAM transaction closed");
            write_envelope(writer, WorkerResponse::Ready { session })
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

fn write_rejection<W: Write>(writer: &mut W, code: WorkerErrorCode) -> Result<(), SessionError> {
    write_envelope(writer, WorkerResponse::Rejected { code })
}
