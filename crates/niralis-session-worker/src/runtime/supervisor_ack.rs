fn peer_credentials(stream: &UnixStream) -> Option<libc::ucred> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        )
    };
    (result == 0).then_some(credentials)
}

/// Waits for the launcher to acknowledge a scope identity it has already
/// persisted. A3.1 calls this between PayloadScopePrepared and CommitExec.
#[cfg_attr(not(test), allow(dead_code))]
fn await_payload_scope_ack(
    worker_id: &str,
    expected_worker_pid: u32,
    registration_nonce: &str,
    deadline: Instant,
) -> Result<(), SessionError> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or(SessionError::WorkerTimedOut)?;
    let signal_fd = worker_signal_fd();
    let supervisor_fd = supervisor_channel_fd();
    let mut pollfds = [
        libc::pollfd {
            fd: signal_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: supervisor_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
    let result = unsafe {
        libc::poll(
            pollfds.as_mut_ptr(),
            pollfds.len() as libc::nfds_t,
            milliseconds,
        )
    };
    if result == 0 {
        return Err(SessionError::WorkerTimedOut);
    }
    if result < 0 {
        return Err(SessionError::WorkerIoFailed);
    }
    if pollfds[0].revents & libc::POLLIN != 0 {
        if let Ok(Some(signal)) = crate::termination::read_signal_fd(signal_fd) {
            emit_fixture_launch_signal(signal);
        }
        return Err(SessionError::AuthenticatedSessionFailed);
    }
    let supervisor_events = pollfds[1].revents;
    if supervisor_events & libc::POLLIN != 0 {
        let mut stream = duplicate_supervisor_channel()?;
        let read_timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|timeout| !timeout.is_zero())
            .ok_or(SessionError::WorkerTimedOut)?;
        stream
            .set_read_timeout(Some(read_timeout))
            .map_err(|_| SessionError::WorkerIoFailed)?;
        match read_control_request(&mut stream) {
            Ok(envelope) if envelope.version == WORKER_CONTROL_PROTOCOL_VERSION => {
                return match envelope.message {
                    WorkerControlRequest::PayloadScopeRegistered {
                        worker_id: ack_worker_id,
                        expected_worker_pid: ack_pid,
                        registration_nonce: ack_nonce,
                    } if ack_worker_id == worker_id
                        && ack_pid == expected_worker_pid
                        && ack_nonce == registration_nonce =>
                    {
                        Ok(())
                    }
                    _ => Err(SessionError::WorkerProtocolFailed),
                };
            }
            Ok(_) => return Err(SessionError::WorkerProtocolFailed),
            Err(error)
                if supervisor_events & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0 =>
            {
                return Err(error)
            }
            Err(_) => {}
        }
    }
    if supervisor_events & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        emit_fixture_event("LaunchSupervisorDisconnected");
        warn!(stage = "ack", "dedicated supervisor channel disconnected");
        return Err(SessionError::AuthenticatedSessionFailed);
    }
    Err(SessionError::WorkerIoFailed)
}
