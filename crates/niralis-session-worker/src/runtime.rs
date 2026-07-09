use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};

use niralis_auth::{Authenticator, PamAuthenticator};
use niralis_session::{
    read_envelope, write_envelope, SessionError, StartedSession, WorkerErrorCode, WorkerRequest,
    WorkerResponse, WorkerSessionFailureCode,
};
use tracing::{debug, info, warn};

pub trait WorkerAuthenticatorFactory: Send + Sync {
    fn build(&self, pam_service: &str) -> Box<dyn Authenticator>;
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
    run_worker_process_with_factory(reader, writer, &PamAuthenticatorFactory)
}

pub fn run_worker_process_with_factory<R: Read, W: Write, F: WorkerAuthenticatorFactory>(
    reader: &mut R,
    writer: &mut W,
    factory: &F,
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
        } => run_pam_session(writer, factory, request, pam_service, password),
    }
}

fn run_pam_session<W: Write, F: WorkerAuthenticatorFactory>(
    writer: &mut W,
    factory: &F,
    request: niralis_session::SessionRequest,
    pam_service: String,
    password: niralis_session::WorkerSecret,
) -> Result<(), SessionError> {
    let authenticator = factory.build(&pam_service);
    let auth_result = authenticator.authenticate(&request.username, password.expose());
    drop(password);
    let mut transaction = match auth_result {
        Ok(transaction) => transaction,
        Err(_) => {
            info!(username = %request.username, session = %request.session.id, "worker PAM authentication failed");
            write_envelope(writer, WorkerResponse::AuthenticationFailed)?;
            return Err(SessionError::AuthenticationFailed);
        }
    };

    let open_result = catch_unwind(AssertUnwindSafe(|| transaction.open_session()));
    let session = StartedSession {
        username: request.username,
        session: request.session,
    };

    match open_result {
        Ok(Ok(())) => {
            info!(username = %session.username, session = %session.session.id, "worker PAM session opened");
            drop(transaction);
            info!(username = %session.username, session = %session.session.id, "worker PAM transaction closed");
            write_envelope(writer, WorkerResponse::Ready { session })
        }
        Ok(Err(_)) => {
            warn!(username = %session.username, session = %session.session.id, "worker PAM session open failed");
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
            warn!(username = %session.username, session = %session.session.id, "worker PAM session open panicked");
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
