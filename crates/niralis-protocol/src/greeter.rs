use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const GREETER_PROTOCOL_VERSION: u16 = 2;
pub const MAX_GREETER_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_GREETER_PAYLOAD_BYTES: usize = 48 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct GreeterHandshake {
    pub protocol_version: u16,
    pub message_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GreeterHandshakeResponse {
    pub protocol_version: u16,
    pub connection_id: GreeterConnectionId,
    pub connection_epoch: u64,
    pub seat: SeatId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GreeterConnectionId(String);

impl GreeterConnectionId {
    pub fn new_for_wire(value: String) -> Self {
        Self(value)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatId(String);

impl SeatId {
    pub fn new_for_wire(value: String) -> Self {
        Self(value)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestId(pub u64);

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginSecret(String);

impl LoginSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn consume(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
    pub fn is_bounded(&self) -> bool {
        let bytes = self.0.as_bytes();
        !bytes.is_empty() && bytes.len() <= 4096 && !bytes.contains(&0)
    }
}

impl fmt::Debug for LoginSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginSecret([redacted])")
    }
}

impl Drop for LoginSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GreeterRequest {
    Status,
    GetUsers,
    GetSessions,
    Login {
        username: String,
        session: String,
        secret: LoginSecret,
    },
    Cancel {
        request_id: RequestId,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GreeterRequestEnvelope {
    pub protocol_version: u16,
    pub message_type: String,
    pub connection_id: GreeterConnectionId,
    pub connection_epoch: u64,
    pub request_id: RequestId,
    pub sequence: u64,
    pub seat: SeatId,
    pub payload_len: usize,
    pub payload: GreeterRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GreeterResponseEnvelope {
    pub request_id: RequestId,
    pub connection_epoch: u64,
    pub result: crate::NiralisResponse,
}

impl GreeterRequestEnvelope {
    pub fn validate_shape(&self) -> Result<(), EnvelopeError> {
        if self.protocol_version != GREETER_PROTOCOL_VERSION {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        if self.sequence == 0 {
            return Err(EnvelopeError::InvalidSequence);
        }
        if self.request_id.0 == 0 {
            return Err(EnvelopeError::InvalidRequestId);
        }
        let actual = serde_json::to_vec(&self.payload)
            .map_err(|_| EnvelopeError::InvalidPayload)?
            .len();
        if actual != self.payload_len || actual > MAX_GREETER_PAYLOAD_BYTES {
            return Err(EnvelopeError::InvalidPayload);
        }
        if let GreeterRequest::Login { secret, .. } = &self.payload {
            if !secret.is_bounded() {
                return Err(EnvelopeError::InvalidPayload);
            }
        }
        let expected = match &self.payload {
            GreeterRequest::Status => "status",
            GreeterRequest::GetUsers => "get_users",
            GreeterRequest::GetSessions => "get_sessions",
            GreeterRequest::Login { .. } => "login",
            GreeterRequest::Cancel { .. } => "cancel",
        };
        if self.message_type != expected {
            return Err(EnvelopeError::UnknownMessageType);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    UnsupportedVersion,
    InvalidSequence,
    InvalidRequestId,
    InvalidPayload,
    UnknownMessageType,
}

#[derive(Debug, Default)]
pub struct MonotonicSequence {
    last: u64,
}

impl MonotonicSequence {
    pub fn accept(&mut self, sequence: u64) -> Result<(), EnvelopeError> {
        if sequence == 0 || sequence <= self.last {
            return Err(EnvelopeError::InvalidSequence);
        }
        self.last = sequence;
        Ok(())
    }
}
