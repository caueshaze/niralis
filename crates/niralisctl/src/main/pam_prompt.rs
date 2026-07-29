use niralis_protocol::{PamMessageStyle, PamPromptEnvelope, PamPromptResponse, PamPromptResponseEnvelope};

fn read_login_response(
    reader: &mut BufReader<UnixStream>,
    line: &mut String,
    request: &NiralisRequest,
    connection_epoch: u64,
    pam_password: &mut Option<String>,
) -> Result<NiralisResponse, CliError> {
    loop {
        line.clear();
        read_greeter_line(reader, line)?;
        if let Ok(response) = serde_json::from_str::<GreeterResponseEnvelope>(line.trim_end()) {
            if response.request_id != RequestId(1)
                || response.connection_epoch != connection_epoch
            {
                return Err(CliError::GreeterProtocol(
                    "response correlation mismatch".to_owned(),
                ));
            }
            return Ok(response.result);
        }
        let prompt: PamPromptEnvelope = serde_json::from_str(line.trim_end())
            .map_err(|_| CliError::GreeterProtocol("invalid PAM prompt envelope".to_owned()))?;
        prompt
            .validate_shape()
            .map_err(|_| CliError::GreeterProtocol("invalid PAM prompt shape".to_owned()))?;
        let response = pam_response_for_prompt(&prompt, request, pam_password)?;
        let payload_len = response
            .encoded_len()
            .map_err(|_| CliError::GreeterProtocol("invalid PAM response".to_owned()))?;
        let envelope = PamPromptResponseEnvelope {
            protocol_version: niralis_protocol::GREETER_PROTOCOL_VERSION,
            message_type: "pam_prompt_response".to_owned(),
            connection_id: prompt.connection_id.clone(),
            connection_epoch: prompt.connection_epoch,
            seat: prompt.seat.clone(),
            request_id: prompt.request_id,
            transaction_id: prompt.transaction_id.clone(),
            conversation_id: prompt.conversation_id.clone(),
            prompt_id: prompt.prompt_id,
            sequence: prompt.sequence,
            style: prompt.style,
            payload_len,
            response,
        };
        envelope
            .validate_shape()
            .map_err(|_| CliError::GreeterProtocol("invalid PAM response shape".to_owned()))?;
        serde_json::to_writer(reader.get_mut(), &envelope)?;
        reader.get_mut().write_all(b"\n")?;
        reader.get_mut().flush()?;
    }
}

fn pam_response_for_prompt(
    prompt: &PamPromptEnvelope,
    request: &NiralisRequest,
    pam_password: &mut Option<String>,
) -> Result<PamPromptResponse, CliError> {
    match prompt.style {
        PamMessageStyle::PromptEchoOff => pam_password
            .take()
            .map(niralis_protocol::LoginSecret::new)
            .map(PamPromptResponse::Secret)
            .ok_or_else(|| CliError::GreeterProtocol("repeated PAM secret prompt".to_owned())),
        PamMessageStyle::PromptEchoOn => match request {
            NiralisRequest::Login { username, .. } => {
                Ok(PamPromptResponse::Text(username.clone()))
            }
            _ => Err(CliError::GreeterProtocol(
                "PAM prompt received for non-login request".to_owned(),
            )),
        },
        PamMessageStyle::Informational | PamMessageStyle::Error => {
            Ok(PamPromptResponse::None)
        }
    }
}
