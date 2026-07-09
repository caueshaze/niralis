use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};

use crate::{SessionError, WorkerEnvelope, MAX_WORKER_MESSAGE_BYTES, WORKER_PROTOCOL_VERSION};

pub(crate) fn write_envelope<T: Serialize, W: Write>(
    writer: &mut W,
    message: T,
) -> Result<(), SessionError> {
    let envelope = WorkerEnvelope {
        version: WORKER_PROTOCOL_VERSION,
        message,
    };
    let payload = serde_json::to_vec(&envelope).map_err(|_| SessionError::WorkerIoFailed)?;
    if payload.len() + 1 > MAX_WORKER_MESSAGE_BYTES {
        return Err(SessionError::WorkerProtocolFailed);
    }
    writer
        .write_all(&payload)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|_| SessionError::WorkerIoFailed)
}

pub(crate) fn read_envelope<T: DeserializeOwned, R: Read>(
    reader: &mut R,
) -> Result<WorkerEnvelope<T>, SessionError> {
    let bytes = read_message_bytes(reader)?;
    parse_envelope_bytes(&bytes)
}

fn read_message_bytes<R: Read>(reader: &mut R) -> Result<Vec<u8>, SessionError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_WORKER_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SessionError::WorkerIoFailed)?;
    if bytes.is_empty() || bytes.len() > MAX_WORKER_MESSAGE_BYTES {
        return Err(SessionError::WorkerProtocolFailed);
    }
    Ok(bytes)
}

fn parse_envelope_bytes<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<WorkerEnvelope<T>, SessionError> {
    let message = std::str::from_utf8(bytes).map_err(|_| SessionError::WorkerProtocolFailed)?;
    let mut lines = message.lines();
    let line = lines.next().ok_or(SessionError::WorkerProtocolFailed)?;
    if line.is_empty() || lines.next().is_some() || !message.ends_with('\n') {
        return Err(SessionError::WorkerProtocolFailed);
    }
    serde_json::from_str(line).map_err(|_| SessionError::WorkerProtocolFailed)
}
