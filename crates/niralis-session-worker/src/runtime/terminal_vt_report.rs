fn begin_terminal_vt_cleanup(
    worker_id: &str,
    registration_nonce: &str,
    identity: &niralis_session::PayloadScopeIdentity,
) -> Result<(UnixStream, u64), SessionError> {
    let mut stream = duplicate_supervisor_channel()?;
    niralis_session::write_control_request(&mut stream, WorkerControlRequest::TerminalVtCleanupIntent {
        worker_id: worker_id.to_owned(), expected_worker_pid: std::process::id(),
        registration_nonce: registration_nonce.to_owned(), scope_identity: identity.clone(),
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|_| SessionError::WorkerIoFailed)?;
    let acknowledgement = read_control_request(&mut stream)?;
    match acknowledgement.message {
        WorkerControlRequest::TerminalVtCleanupIntentAcknowledged { worker_id: id, expected_worker_pid, registration_nonce: nonce, attempt_id }
            if acknowledgement.version == WORKER_CONTROL_PROTOCOL_VERSION && id == worker_id
                && expected_worker_pid == std::process::id() && nonce == registration_nonce => Ok((stream, attempt_id)),
        _ => Err(SessionError::WorkerProtocolFailed),
    }
}

fn complete_terminal_vt_cleanup(
    mut stream: UnixStream,
    worker_id: &str,
    registration_nonce: &str,
    attempt_id: u64,
    result: niralis_session::TerminalVtCleanupResult,
) -> Result<(), SessionError> {
    niralis_session::write_control_request(&mut stream, WorkerControlRequest::TerminalVtCleanupResult {
        worker_id: worker_id.to_owned(), expected_worker_pid: std::process::id(),
        registration_nonce: registration_nonce.to_owned(), attempt_id, result,
    })?;
    let acknowledgement = read_control_request(&mut stream)?;
    match acknowledgement.message {
        WorkerControlRequest::TerminalVtCleanupResultAcknowledged { worker_id: id, expected_worker_pid, registration_nonce: nonce, attempt_id: acknowledged }
            if acknowledgement.version == WORKER_CONTROL_PROTOCOL_VERSION && id == worker_id
                && expected_worker_pid == std::process::id() && nonce == registration_nonce && acknowledged == attempt_id => Ok(()),
        _ => Err(SessionError::WorkerProtocolFailed),
    }
}
