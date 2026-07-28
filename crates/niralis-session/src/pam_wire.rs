impl PamConversationAuthority {
    pub(crate) fn accept_wire_prompt(
        &mut self,
        prompt: &PamPromptEnvelope,
    ) -> Result<(), PamConversationError> {
        if self.consumed || self.deadline <= Instant::now() {
            self.consumed = true;
            return Err(PamConversationError::ConversationConsumed);
        }
        if prompt.conversation_id != self.conversation_id
            || prompt.connection_id.as_str() != self.connection_id
            || prompt.connection_epoch != self.connection_epoch
            || prompt.request_id.0 != self.request_id
            || prompt.seat.as_str() != self.seat
            || prompt.transaction_id != self.transaction_id
            || prompt.sequence != self.next_sequence
            || prompt.prompt_id.0 == 0
            || self.pending.is_some()
        {
            return Err(PamConversationError::InvalidSequence);
        }
        self.next_sequence += 1;
        self.pending = Some((prompt.prompt_id, prompt.style, prompt.sequence));
        Ok(())
    }
    pub(crate) fn accept_wire_response(
        &mut self,
        response: &PamPromptResponseEnvelope,
    ) -> Result<(), PamConversationError> {
        if self.consumed || self.deadline <= Instant::now() {
            self.consumed = true;
            return Err(PamConversationError::ConversationConsumed);
        }
        let Some((prompt_id, style, sequence)) = self.pending else {
            return Err(PamConversationError::UnknownPrompt);
        };
        if response.conversation_id != self.conversation_id
            || response.connection_id.as_str() != self.connection_id
            || response.connection_epoch != self.connection_epoch
            || response.request_id.0 != self.request_id
            || response.seat.as_str() != self.seat
            || response.transaction_id != self.transaction_id
            || response.prompt_id != prompt_id
            || response.style != style
            || response.sequence != sequence
        {
            return Err(PamConversationError::IncompatibleResponse);
        }
        self.pending = None;
        Ok(())
    }
}
