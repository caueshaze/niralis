use niralis_auth::{PamConversationDriver, PamConversationError};
use niralis_protocol::{
    GreeterConnectionId, PamConversationId, PamMessageStyle, PamPromptEnvelope,
    PamPromptId, PamPromptResponse, RequestId, SeatId,
};
use niralis_session::{LoginRequestBinding, WorkerTransactionIdentity};

pub(crate) struct WorkerPamConversationDriver {
    binding: LoginRequestBinding,
    conversation_id: PamConversationId,
    transaction: WorkerTransactionIdentity,
    worker_id: String,
    worker_pid: u32,
    prompt_id: u64,
    sequence: u64,
}

impl WorkerPamConversationDriver {
    pub(crate) fn new(
        binding: LoginRequestBinding,
        conversation_id: PamConversationId,
        transaction: WorkerTransactionIdentity,
        worker_id: String,
        worker_pid: u32,
    ) -> Self {
        Self { binding, conversation_id, transaction, worker_id, worker_pid, prompt_id: 0, sequence: 0 }
    }

    fn stdout() -> Result<std::fs::File, ()> {
        let duplicate = unsafe { libc::dup(libc::STDOUT_FILENO) };
        if duplicate < 0 { return Err(()); }
        Ok(unsafe {
            <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(
                duplicate as std::os::fd::RawFd,
            )
        })
    }
}

impl PamConversationDriver for WorkerPamConversationDriver {
    fn respond(
        &mut self,
        style: PamMessageStyle,
        message: &std::ffi::CStr,
    ) -> Result<PamPromptResponse, PamConversationError> {
        self.prompt_id = self.prompt_id.checked_add(1).ok_or(PamConversationError)?;
        self.sequence = self.sequence.checked_add(1).ok_or(PamConversationError)?;
        let message = message.to_str().map_err(|_| PamConversationError)?.to_owned();
        if message.is_empty() || message.len() > 4096 { return Err(PamConversationError); }
        let prompt = PamPromptEnvelope {
            protocol_version: niralis_protocol::GREETER_PROTOCOL_VERSION,
            message_type: "pam_prompt".to_owned(),
            connection_id: GreeterConnectionId::new_for_wire(self.binding.connection_id.clone()),
            connection_epoch: self.binding.connection_epoch,
            seat: SeatId::new_for_wire(self.binding.seat.clone()),
            request_id: RequestId(self.binding.request_id),
            transaction_id: self.transaction.transaction_id.clone(),
            conversation_id: self.conversation_id.clone(),
            prompt_id: PamPromptId(self.prompt_id),
            sequence: self.sequence,
            style,
            payload_len: message.len(),
            message,
        };
        let mut stdout = Self::stdout().map_err(|_| PamConversationError)?;
        write_envelope(&mut stdout, WorkerResponse::PamPrompt {
            worker_id: self.worker_id.clone(), expected_worker_pid: self.worker_pid,
            transaction: self.transaction.clone(), prompt: prompt.clone(),
        }).map_err(|_| PamConversationError)?;
        drop(stdout);

        let mut control = duplicate_supervisor_channel().map_err(|_| PamConversationError)?;
        let response = read_control_request(&mut control).map_err(|_| PamConversationError)?;
        if response.version != WORKER_CONTROL_PROTOCOL_VERSION { return Err(PamConversationError); }
        let response = match response.message {
            WorkerControlRequest::PamPromptResponse { transaction, worker_id, expected_worker_pid, response }
                if worker_id == self.worker_id && expected_worker_pid == self.worker_pid
                    && transaction.matches_worker(&self.transaction, "pam_prompt_response", self.sequence)
                    && response.connection_id.as_str() == self.binding.connection_id
                    && response.connection_epoch == self.binding.connection_epoch
                    && response.seat.as_str() == self.binding.seat
                    && response.request_id.0 == self.binding.request_id
                    && response.transaction_id == self.transaction.transaction_id
                    && response.conversation_id == self.conversation_id
                    && response.prompt_id.0 == self.prompt_id
                    && response.sequence == self.sequence
                    && response.style == style => response,
            _ => return Err(PamConversationError),
        };
        response.validate_shape().map_err(|_| PamConversationError)?;
        Ok(response.response)
    }
}
