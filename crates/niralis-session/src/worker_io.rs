use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroizing;

use crate::{SessionError, WorkerEnvelope, MAX_WORKER_MESSAGE_BYTES, WORKER_PROTOCOL_VERSION};
use crate::{
    WorkerControlRequest, MAX_WORKER_CONTROL_MESSAGE_BYTES, WORKER_CONTROL_PROTOCOL_VERSION,
};

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

pub fn write_control_request<W: Write>(
    writer: &mut W,
    request: WorkerControlRequest,
) -> Result<(), SessionError> {
    let envelope = WorkerEnvelope {
        version: WORKER_CONTROL_PROTOCOL_VERSION,
        message: request,
    };
    let payload = serde_json::to_vec(&envelope).map_err(|_| SessionError::WorkerIoFailed)?;
    if payload.len() + 1 > MAX_WORKER_CONTROL_MESSAGE_BYTES {
        return Err(SessionError::WorkerProtocolFailed);
    }
    writer
        .write_all(&payload)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|_| SessionError::WorkerIoFailed)
}

pub fn read_control_request<R: Read>(
    reader: &mut R,
) -> Result<WorkerEnvelope<WorkerControlRequest>, SessionError> {
    let bytes = read_control_message_bytes(reader)?;
    if !bytes.ends_with(b"\n") {
        return Err(SessionError::WorkerProtocolFailed);
    }
    serde_json::from_slice(&bytes[..bytes.len() - 1])
        .map_err(|_| SessionError::WorkerProtocolFailed)
}

fn read_control_message_bytes<R: Read>(reader: &mut R) -> Result<Vec<u8>, SessionError> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .map_err(|_| SessionError::WorkerIoFailed)?;
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            return if bytes.len() <= MAX_WORKER_CONTROL_MESSAGE_BYTES {
                Ok(bytes)
            } else {
                Err(SessionError::WorkerProtocolFailed)
            };
        }
        if bytes.len() >= MAX_WORKER_CONTROL_MESSAGE_BYTES {
            return Err(SessionError::WorkerProtocolFailed);
        }
    }
}

fn read_message_bytes<R: Read>(reader: &mut R) -> Result<Zeroizing<Vec<u8>>, SessionError> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        if let Err(error) = reader.read_exact(&mut byte) {
            return Err(if error.kind() == std::io::ErrorKind::UnexpectedEof {
                SessionError::WorkerProtocolFailed
            } else {
                SessionError::WorkerIoFailed
            });
        }
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() > MAX_WORKER_MESSAGE_BYTES {
            return Err(SessionError::WorkerProtocolFailed);
        }
    }
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
