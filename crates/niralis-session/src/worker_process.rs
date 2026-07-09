use std::io::{Read, Write};

use tracing::{debug, info};

use crate::{
    protocol::WorkerEnvelope,
    worker_io::{read_envelope, write_envelope},
    SessionError, StartedSession, WorkerErrorCode, WorkerRequest, WorkerResponse,
    WORKER_PROTOCOL_VERSION,
};

pub fn run_worker_process<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), SessionError> {
    match read_envelope::<WorkerRequest, _>(reader) {
        Ok(envelope) if envelope.version != WORKER_PROTOCOL_VERSION => {
            info!("worker rejected unsupported protocol version");
            write_rejection(writer, WorkerErrorCode::UnsupportedVersion)?;
            Err(SessionError::WorkerRejected)
        }
        Ok(WorkerEnvelope {
            message: WorkerRequest::PrepareSession { request },
            ..
        }) => {
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
        Err(SessionError::WorkerProtocolFailed) => {
            debug!("worker rejected invalid request");
            write_rejection(writer, WorkerErrorCode::InvalidRequest)?;
            Err(SessionError::WorkerRejected)
        }
        Err(_) => {
            debug!("worker failed while reading request");
            write_rejection(writer, WorkerErrorCode::InternalError)?;
            Err(SessionError::WorkerRejected)
        }
    }
}

fn write_rejection<W: Write>(writer: &mut W, code: WorkerErrorCode) -> Result<(), SessionError> {
    write_envelope(writer, WorkerResponse::Rejected { code })
}
