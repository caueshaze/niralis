use niralis_protocol::{
    PamConversationId, PamMessageStyle, PamPromptEnvelope, PamPromptId, PamPromptResponse,
    PamPromptResponseEnvelope,
};
use std::time::Instant;
const MAX_PROMPT_BYTES: usize = 4096;
const MAX_RESPONSE_BYTES: usize = 4096;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PamConversationError {
    InvalidIdentity,
    InvalidSequence,
    InvalidPrompt,
    DuplicatePrompt,
    PromptAlreadyPending,
    UnknownPrompt,
    IncompatibleResponse,
    ConversationConsumed,
    DeadlineExpired,
}
#[derive(Debug, PartialEq, Eq)]
pub struct PamPrompt {
    pub id: PamPromptId,
    pub sequence: u64,
    pub style: PamMessageStyle,
    pub message: String,
}
#[derive(Debug)]
pub struct PamConversationAuthority {
    transaction_id: String,
    admission_attempt_id: u64,
    lifecycle_id: String,
    seat: String,
    seat_generation: u64,
    connection_id: String,
    connection_epoch: u64,
    request_id: u64,
    worker_id: String,
    conversation_id: PamConversationId,
    next_sequence: u64,
    deadline: Instant,
    consumed: bool,
    pending: Option<(PamPromptId, PamMessageStyle, u64)>,
}
#[derive(Debug)]
pub struct PendingPamPrompt {
    authority: PamConversationAuthority,
    prompt: PamPrompt,
}
#[derive(Debug)]
pub struct AuthenticatedConversation {
    authority: PamConversationAuthority,
}
#[derive(Debug)]
pub struct FailedConversation {
    authority: PamConversationAuthority,
}
impl PamConversationAuthority {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue(
        transaction_id: String,
        admission_attempt_id: u64,
        lifecycle_id: String,
        seat: String,
        seat_generation: u64,
        connection_id: String,
        connection_epoch: u64,
        request_id: u64,
        worker_id: String,
        conversation_id: PamConversationId,
        deadline: Instant,
    ) -> Result<Self, PamConversationError> {
        if transaction_id.is_empty()
            || admission_attempt_id == 0
            || lifecycle_id.is_empty()
            || seat.is_empty()
            || seat_generation == 0
            || connection_id.is_empty()
            || connection_epoch == 0
            || request_id == 0
            || worker_id.is_empty()
            || conversation_id.as_str().is_empty()
        {
            return Err(PamConversationError::InvalidIdentity);
        }
        Ok(Self {
            transaction_id,
            admission_attempt_id,
            lifecycle_id,
            seat,
            seat_generation,
            connection_id,
            connection_epoch,
            request_id,
            worker_id,
            conversation_id,
            next_sequence: 1,
            deadline,
            consumed: false,
            pending: None,
        })
    }
    pub fn conversation_id(&self) -> &PamConversationId {
        &self.conversation_id
    }
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
    pub fn connection_epoch(&self) -> u64 {
        self.connection_epoch
    }
    #[allow(clippy::too_many_arguments)]
    pub fn matches_transaction(
        &self,
        transaction_id: &str,
        admission_attempt_id: u64,
        lifecycle_id: &str,
        seat: &str,
        seat_generation: u64,
        connection_id: &str,
        connection_epoch: u64,
        worker_id: &str,
    ) -> bool {
        self.transaction_id == transaction_id
            && self.admission_attempt_id == admission_attempt_id
            && self.lifecycle_id == lifecycle_id
            && self.seat == seat
            && self.seat_generation == seat_generation
            && self.connection_id == connection_id
            && self.connection_epoch == connection_epoch
            && self.worker_id == worker_id
    }
    #[allow(clippy::result_large_err)]
    pub fn prompt(
        mut self,
        id: PamPromptId,
        sequence: u64,
        style: PamMessageStyle,
        message: String,
    ) -> Result<PendingPamPrompt, (PamConversationError, Self)> {
        if self.consumed {
            return Err((PamConversationError::ConversationConsumed, self));
        }
        if self.deadline <= Instant::now() {
            self.consumed = true;
            return Err((PamConversationError::DeadlineExpired, self));
        }
        if id.0 == 0
            || sequence != self.next_sequence
            || message.is_empty()
            || message.len() > MAX_PROMPT_BYTES
            || message.as_bytes().contains(&0)
        {
            return Err((PamConversationError::InvalidPrompt, self));
        }
        self.next_sequence += 1;
        Ok(PendingPamPrompt {
            authority: self,
            prompt: PamPrompt {
                id,
                sequence,
                style,
                message,
            },
        })
    }
    pub fn fail(mut self) -> FailedConversation {
        self.consumed = true;
        FailedConversation { authority: self }
    }
    #[allow(clippy::result_large_err)]
    pub fn authenticated(
        mut self,
    ) -> Result<AuthenticatedConversation, (PamConversationError, Self)> {
        if self.consumed {
            return Err((PamConversationError::ConversationConsumed, self));
        }
        if self.deadline <= Instant::now() {
            self.consumed = true;
            return Err((PamConversationError::DeadlineExpired, self));
        }
        self.consumed = true;
        Ok(AuthenticatedConversation { authority: self })
    }
}
include!("pam_wire.rs");
impl PendingPamPrompt {
    pub fn prompt(&self) -> &PamPrompt {
        &self.prompt
    }
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub fn respond(
        self,
        transaction_id: &str,
        connection_id: &str,
        connection_epoch: u64,
        worker_id: &str,
        prompt_id: PamPromptId,
        style: PamMessageStyle,
        response: PamPromptResponse,
    ) -> Result<(PamConversationAuthority, PamPromptResponse), (PamConversationError, Self)> {
        if self.authority.consumed {
            return Err((PamConversationError::ConversationConsumed, self));
        }
        if prompt_id != self.prompt.id
            || style != self.prompt.style
            || self.authority.transaction_id != transaction_id
            || self.authority.connection_id != connection_id
            || self.authority.connection_epoch != connection_epoch
            || self.authority.worker_id != worker_id
        {
            return Err((PamConversationError::IncompatibleResponse, self));
        }
        let valid = match (&style, &response) {
            (PamMessageStyle::PromptEchoOff, PamPromptResponse::Secret(secret)) => {
                secret.is_bounded()
            }
            (PamMessageStyle::PromptEchoOn, PamPromptResponse::Text(text)) => {
                !text.is_empty()
                    && text.len() <= MAX_RESPONSE_BYTES
                    && !text.as_bytes().contains(&0)
            }
            (PamMessageStyle::Informational | PamMessageStyle::Error, PamPromptResponse::None) => {
                true
            }
            _ => false,
        };
        if !valid {
            return Err((PamConversationError::IncompatibleResponse, self));
        }
        Ok((self.authority, response))
    }
}
impl AuthenticatedConversation {
    pub fn transaction_id(&self) -> &str {
        &self.authority.transaction_id
    }
}
impl FailedConversation {
    pub fn transaction_id(&self) -> &str {
        &self.authority.transaction_id
    }
}
