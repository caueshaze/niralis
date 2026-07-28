#[allow(clippy::too_many_arguments)]
fn forward_pam_prompt(
    attempt: &mut WorkerAttempt,
    event_worker_id: String,
    expected_worker_pid: u32,
    transaction: crate::WorkerTransactionIdentity,
    prompt: niralis_protocol::PamPromptEnvelope,
    worker_id: &str,
    worker_pid: u32,
    generation: u64,
    attempt_id: u64,
    conversation: Option<&std::sync::Arc<dyn crate::PamConversationTransport>>,
    mut pam_authority: Option<&mut crate::PamConversationAuthority>,
) -> Result<(), SessionError> {
    if event_worker_id != worker_id
        || expected_worker_pid != worker_pid
        || prompt.validate_shape().is_err()
        || !valid_transaction(&transaction, worker_id, generation, attempt_id, "reserved")
    {
        return Err(SessionError::WorkerProtocolFailed);
    }
    let transport = conversation.ok_or(SessionError::WorkerProtocolFailed)?;
    pam_authority
        .as_mut()
        .ok_or(SessionError::WorkerProtocolFailed)?
        .accept_wire_prompt(&prompt)
        .map_err(|_| SessionError::WorkerProtocolFailed)?;
    let response = transport.round_trip(prompt.clone())?;
    if response.connection_id != prompt.connection_id
        || response.connection_epoch != prompt.connection_epoch
        || response.seat != prompt.seat
        || response.request_id != prompt.request_id
        || response.transaction_id != prompt.transaction_id
        || response.conversation_id != prompt.conversation_id
        || response.prompt_id != prompt.prompt_id
        || response.sequence != prompt.sequence
        || response.style != prompt.style
    {
        return Err(SessionError::WorkerProtocolFailed);
    }
    response.validate_shape().map_err(|_| SessionError::WorkerProtocolFailed)?;
    pam_authority
        .ok_or(SessionError::WorkerProtocolFailed)?
        .accept_wire_response(&response)
        .map_err(|_| SessionError::WorkerProtocolFailed)?;
    attempt.send_supervisor_control_request(crate::WorkerControlRequest::PamPromptResponse {
        transaction: crate::ControlTransactionIdentity::from_worker(
            &transaction, "pam_prompt_response", prompt.sequence,
        ),
        worker_id: worker_id.to_owned(), expected_worker_pid, response,
    })
}
