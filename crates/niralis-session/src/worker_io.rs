use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroizing;

use crate::{SessionError, WorkerEnvelope, MAX_WORKER_MESSAGE_BYTES, WORKER_PROTOCOL_VERSION};

pub fn write_envelope<T: Serialize, W: Write>(
    writer: &mut W,
    message: T,
) -> Result<(), SessionError> {
    let envelope = WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message,
    };
    let payload =
        Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| SessionError::WorkerIoFailed)?);
    if payload.len() + 1 > MAX_WORKER_MESSAGE_BYTES {
        return Err(SessionError::WorkerProtocolFailed);
    }
    writer
        .write_all(payload.as_slice())
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|_| SessionError::WorkerIoFailed)
}

pub fn read_envelope<T: DeserializeOwned, R: Read>(
    reader: &mut R,
) -> Result<WorkerEnvelope<T>, SessionError> {
    let bytes = read_message_bytes(reader)?;
    parse_envelope_bytes(bytes.as_slice())
}

fn read_message_bytes<R: Read>(reader: &mut R) -> Result<Zeroizing<Vec<u8>>, SessionError> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_WORKER_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut *bytes)
        .map_err(|_| SessionError::WorkerIoFailed)?;
    if bytes.is_empty() || bytes.len() > MAX_WORKER_MESSAGE_BYTES {
        return Err(SessionError::WorkerProtocolFailed);
    }
    Ok(bytes)
}

fn parse_envelope_bytes<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<WorkerEnvelope<T>, SessionError> {
    if !bytes.ends_with(b"\n") {
        return Err(SessionError::WorkerProtocolFailed);
    }
    let line = &bytes[..bytes.len() - 1];
    if line.is_empty() || line.contains(&b'\n') {
        return Err(SessionError::WorkerProtocolFailed);
    }
    serde_json::from_slice(line).map_err(|_| SessionError::WorkerProtocolFailed)
}
