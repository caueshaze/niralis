#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadScopeReleaseOutcome {
    Released,
    RecoveryRequired,
}

#[allow(clippy::too_many_arguments)]
fn request_payload_scope_release<W: Write>(
    writer: &mut W,
    worker_id: &str,
    registration_nonce: &str,
    identity: &niralis_session::PayloadScopeIdentity,
    local_cleanup_succeeded: bool,
    deadline: Instant,
) -> Result<PayloadScopeReleaseOutcome, SessionError> {
    write_envelope(
        writer,
        WorkerResponse::PayloadScopeReleaseReady {
            worker_id: worker_id.to_owned(),
        },
    )?;
    info!(unit = %identity.unit_name, local_cleanup_succeeded, "payload scope release requested after post-ack launch failure");
    let mut stream = duplicate_supervisor_channel()?;
    let release_nonce = random_release_nonce()?;
    niralis_session::write_control_request(
        &mut stream,
        WorkerControlRequest::PayloadScopeReleaseRequested {
            worker_id: worker_id.to_owned(),
            expected_worker_pid: std::process::id(),
            registration_nonce: registration_nonce.to_owned(),
            release_nonce: release_nonce.clone(),
            scope_identity: identity.clone(),
            local_cleanup_succeeded,
        },
    )?;
    emit_fixture_event("PayloadScopeReleaseRequested:count=1");
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or(SessionError::WorkerTimedOut)?;
    let mut pollfd = libc::pollfd {
        fd: supervisor_channel_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe {
        libc::poll(
            &mut pollfd,
            1,
            timeout.as_millis().min(i32::MAX as u128) as i32,
        )
    };
    if result == 0 {
        return Err(SessionError::WorkerTimedOut);
    }
    if result < 0 {
        return Err(SessionError::WorkerIoFailed);
    }
    if pollfd.revents & libc::POLLIN == 0 {
        if pollfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            warn!(
                stage = "release",
                "dedicated supervisor channel disconnected"
            );
        }
        return Err(SessionError::WorkerIoFailed);
    }
    let read_timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|timeout| !timeout.is_zero())
        .ok_or(SessionError::WorkerTimedOut)?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|_| SessionError::WorkerIoFailed)?;
    let response = read_control_request(&mut stream)?;
    if response.version != WORKER_CONTROL_PROTOCOL_VERSION {
        return Err(SessionError::WorkerProtocolFailed);
    }
    match response.message {
        WorkerControlRequest::PayloadScopeReleased {
            worker_id: response_worker_id,
            expected_worker_pid,
            registration_nonce: response_registration_nonce,
            release_nonce: response_release_nonce,
        } if response_worker_id == worker_id
            && expected_worker_pid == std::process::id()
            && response_registration_nonce == registration_nonce
            && response_release_nonce == release_nonce =>
        {
            info!(unit = %identity.unit_name, "payload scope release independently verified and acknowledged");
            Ok(PayloadScopeReleaseOutcome::Released)
        }
        WorkerControlRequest::PayloadScopeRecoveryRequired {
            worker_id: response_worker_id,
            expected_worker_pid,
            registration_nonce: response_registration_nonce,
            release_nonce: response_release_nonce,
            reason,
        } if response_worker_id == worker_id
            && expected_worker_pid == std::process::id()
            && response_registration_nonce == registration_nonce
            && response_release_nonce == release_nonce =>
        {
            warn!(?reason, unit = %identity.unit_name, "supervisor could not prove payload scope cleanup; recovery required");
            Ok(PayloadScopeReleaseOutcome::RecoveryRequired)
        }
        _ => Err(SessionError::WorkerProtocolFailed),
    }
}

fn random_release_nonce() -> Result<String, SessionError> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| SessionError::WorkerIoFailed)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
