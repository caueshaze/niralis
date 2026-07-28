use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{
    EnvelopeError, GreeterConnectionId, LoginSecret, RequestId, SeatId, GREETER_PROTOCOL_VERSION,
    MAX_GREETER_PAYLOAD_BYTES,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PamConversationId(String);
impl PamConversationId {
    pub fn new_for_wire(value: String) -> Self {
        Self(value)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PamPromptId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PamMessageStyle {
    PromptEchoOff,
    PromptEchoOn,
    Informational,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PamPromptEnvelope {
    pub protocol_version: u16,
    pub message_type: String,
    pub connection_id: GreeterConnectionId,
    pub connection_epoch: u64,
    pub seat: SeatId,
    pub request_id: RequestId,
    pub transaction_id: String,
    pub conversation_id: PamConversationId,
    pub prompt_id: PamPromptId,
    pub sequence: u64,
    pub style: PamMessageStyle,
    pub payload_len: usize,
    pub message: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PamPromptResponseEnvelope {
    pub protocol_version: u16,
    pub message_type: String,
    pub connection_id: GreeterConnectionId,
    pub connection_epoch: u64,
    pub seat: SeatId,
    pub request_id: RequestId,
    pub transaction_id: String,
    pub conversation_id: PamConversationId,
    pub prompt_id: PamPromptId,
    pub sequence: u64,
    pub style: PamMessageStyle,
    pub payload_len: usize,
    pub response: PamPromptResponse,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub enum PamPromptResponse {
    Secret(LoginSecret),
    Text(String),
    None,
}
impl fmt::Debug for PamPromptResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret(_) => f.write_str("PamPromptResponse::Secret([redacted])"),
            Self::Text(_) => f.write_str("PamPromptResponse::Text([redacted])"),
            Self::None => f.write_str("PamPromptResponse::None"),
        }
    }
}
impl PamPromptResponse {
    pub fn encoded_len(&self) -> Result<usize, serde_json::Error> {
        serde_json::to_vec(self).map(|v| v.len())
    }
}

impl PamPromptEnvelope {
    pub fn validate_shape(&self) -> Result<(), EnvelopeError> {
        if self.protocol_version != GREETER_PROTOCOL_VERSION
            || self.message_type != "pam_prompt"
            || self.request_id.0 == 0
            || self.sequence == 0
            || self.connection_epoch == 0
            || self.transaction_id.is_empty()
            || self.seat.as_str().is_empty()
            || self.conversation_id.as_str().is_empty()
            || self.prompt_id.0 == 0
            || self.message.is_empty()
            || self.message.len() > 4096
            || self.message.as_bytes().contains(&0)
            || self.message.len() != self.payload_len
            || self.message.len() > MAX_GREETER_PAYLOAD_BYTES
        {
            return Err(EnvelopeError::InvalidPayload);
        }
        Ok(())
    }
}
impl PamPromptResponseEnvelope {
    pub fn validate_shape(&self) -> Result<(), EnvelopeError> {
        if self.protocol_version != GREETER_PROTOCOL_VERSION
            || self.message_type != "pam_prompt_response"
            || self.request_id.0 == 0
            || self.sequence == 0
            || self.connection_epoch == 0
            || self.transaction_id.is_empty()
            || self.seat.as_str().is_empty()
            || self.conversation_id.as_str().is_empty()
            || self.prompt_id.0 == 0
        {
            return Err(EnvelopeError::InvalidPayload);
        }
        let actual = self
            .response
            .encoded_len()
            .map_err(|_| EnvelopeError::InvalidPayload)?;
        if actual != self.payload_len || actual > MAX_GREETER_PAYLOAD_BYTES {
            return Err(EnvelopeError::InvalidPayload);
        }
        match (&self.style, &self.response) {
            (PamMessageStyle::PromptEchoOff, PamPromptResponse::Secret(secret))
                if secret.is_bounded() =>
            {
                Ok(())
            }
            (PamMessageStyle::PromptEchoOn, PamPromptResponse::Text(text))
                if !text.is_empty() && text.len() <= 4096 && !text.as_bytes().contains(&0) =>
            {
                Ok(())
            }
            (PamMessageStyle::Informational | PamMessageStyle::Error, PamPromptResponse::None) => {
                Ok(())
            }
            _ => Err(EnvelopeError::InvalidPayload),
        }
    }
}
