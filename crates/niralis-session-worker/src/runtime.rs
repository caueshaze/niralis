use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};

use niralis_auth::{AuthError, Authenticator, PamAuthenticator};
use niralis_session::{
    read_envelope, write_envelope, SessionError, StartedSession, WorkerErrorCode, WorkerRequest,
    WorkerResponse, WorkerSessionFailureCode,
};
use tracing::{debug, info, warn};

use crate::identity::{NssUnixIdentityResolver, UnixIdentityResolver};

pub trait WorkerAuthenticatorFactory: Send + Sync {
    fn build(&self, pam_service: &str) -> Box<dyn Authenticator>;
}

pub struct WorkerDependencies<'a, F, I> {
    pub authenticator_factory: &'a F,
    pub identity_resolver: &'a I,
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
        },
    )
}

pub fn run_worker_process_with_dependencies<
    R: Read,
    W: Write,
    F: WorkerAuthenticatorFactory,
    I: UnixIdentityResolver,
>(
    reader: &mut R,
    writer: &mut W,
    dependencies: WorkerDependencies<'_, F, I>,
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
        } => run_pam_session(
            writer,
            dependencies.authenticator_factory,
            dependencies.identity_resolver,
            request,
            pam_service,
            password,
        ),
    }
}

fn run_pam_session<W: Write, F: WorkerAuthenticatorFactory, I: UnixIdentityResolver>(
    writer: &mut W,
    factory: &F,
    identity_resolver: &I,
    request: niralis_session::SessionRequest,
    pam_service: String,
    password: niralis_session::WorkerSecret,
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
    debug!(
        username = %identity.username,
        uid = identity.uid,
        gid = identity.gid,
        "resolved canonical Unix identity"
    );
    let canonical_username = identity.username.clone();

    let open_result = catch_unwind(AssertUnwindSafe(|| transaction.open_session()));
    let session = StartedSession {
        username: request.username,
        session: request.session,
    };

    match open_result {
        Ok(Ok(())) => {
            info!(username = %canonical_username, session = %session.session.id, "worker PAM session opened");
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
