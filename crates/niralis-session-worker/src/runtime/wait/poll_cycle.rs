{
        let mut fds = [
            libc::pollfd {
                fd: if leader_reaped { -1 } else { pidfd },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: listener.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signal_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: coordinator.timer_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: supervisor_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: observer.as_ref().map_or(-1, |value| value.as_raw_fd()),
                events: observer.as_ref().map_or(0, |value| value.poll_events()),
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Ok(SessionWaitResult::Graceful(
                coordinator.infrastructure(GracefulTerminationError::Poll),
            ));
        }
        let mut trigger = None;
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 && !leader_reaped {
            let status = match child_runner.poll_child() {
                Ok(status) => status,
                Err(_) => {
                    return Ok(SessionWaitResult::Graceful(
                        coordinator.infrastructure(GracefulTerminationError::LeaderReap),
                    ))
                }
            };
            if let Some(status) = status {
                let exit = LeaderExit::from_status(status);
                info!(?exit, "authoritative session leader exited");
                coordinator.record_leader_exit(exit.clone());
                leader_reaped = true;
                trigger = Some(TerminationCause::LeaderExited(exit));
            }
        }
        if fds[5].revents != 0 {
            let Some(boundary_observer) = observer.as_mut() else {
                return Ok(SessionWaitResult::Graceful(
                    coordinator.infrastructure(GracefulTerminationError::BoundaryObserver),
                ));
            };
            if boundary_observer.consume_wakeup().is_err() {
                return Ok(SessionWaitResult::Graceful(
                    coordinator.infrastructure(GracefulTerminationError::BoundaryObserver),
                ));
            }
            match authoritative_scope.boundary_appears_terminal() {
                Ok(true) => {
                    emit_fixture_event("BoundaryCandidate");
                    return Ok(SessionWaitResult::Graceful(coordinator.boundary_candidate(
                        BoundaryTerminalObservation::CgroupEventRevalidated,
                    )));
                }
                Ok(false) => {}
                Err(error) => {
                    return Ok(SessionWaitResult::Graceful(coordinator.scope_error(error)))
                }
            }
        }
        if fds[2].revents & libc::POLLIN != 0 {
            loop {
                let signal = match crate::termination::read_signal_fd(signal_fd) {
                    Ok(Some(signal)) => signal,
                    Ok(None) => break,
                    Err(_) => {
                        return Ok(SessionWaitResult::Graceful(
                            coordinator.infrastructure(GracefulTerminationError::Signal),
                        ))
                    }
                };
                let name = match signal {
                    libc::SIGTERM => "SIGTERM",
                    libc::SIGINT => "SIGINT",
                    libc::SIGHUP => "SIGHUP",
                    _ => "UNKNOWN",
                };
                info!(signal = name, "worker signal received");
                let Some(signal) = WorkerTerminationSignal::from_raw(signal) else {
                    return Ok(SessionWaitResult::Graceful(
                        coordinator.infrastructure(GracefulTerminationError::Signal),
                    ));
                };
                trigger.get_or_insert(TerminationCause::WorkerSignal(signal));
            }
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            warn!("control channel disconnected; terminating session");
            trigger.get_or_insert(TerminationCause::SupervisorDisconnected);
        }
        if fds[4].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            warn!("supervisor channel disconnected; terminating session");
            trigger.get_or_insert(TerminationCause::SupervisorDisconnected);
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let Some(listener) = listener.as_ref() else {
                return Ok(SessionWaitResult::Graceful(
                    coordinator.infrastructure(GracefulTerminationError::Control),
                ));
            };
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if !peer_has_uid(&stream, expected_control_uid) {
                        continue;
                    }
                    let request = match read_control_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => {
                            return Ok(SessionWaitResult::Graceful(
                                coordinator.infrastructure(GracefulTerminationError::Control),
                            ))
                        }
                    };
                    if request.version != WORKER_CONTROL_PROTOCOL_VERSION {
                        return Ok(SessionWaitResult::Graceful(
                            coordinator.infrastructure(GracefulTerminationError::Control),
                        ));
                    }
                    match request.message {
                        WorkerControlRequest::PayloadScopeRegistered { .. } => {
                            return Ok(SessionWaitResult::Graceful(
                                coordinator.infrastructure(GracefulTerminationError::Control),
                            ));
                        }
                        WorkerControlRequest::Terminate {
                            worker_id: requested_worker_id,
                            expected_worker_pid,
                            expected_session_pid,
                            expected_session_pgid,
                        } if requested_worker_id == worker_id
                            && expected_worker_pid == std::process::id()
                            && expected_session_pid == session_pid
                            && expected_session_pgid == session_pgid =>
                        {
                            trigger.get_or_insert(TerminationCause::InternalTerminateRequest);
                        }
                        _ => {
                            return Ok(SessionWaitResult::Graceful(
                                coordinator.infrastructure(GracefulTerminationError::Control),
                            ))
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    return Ok(SessionWaitResult::Graceful(
                        coordinator.infrastructure(GracefulTerminationError::Control),
                    ))
                }
            }
        }
        if let Some(new_cause) = trigger {
            if let Some(original) = coordinator.cause() {
                info!(original_cause = ?original, new_cause = ?new_cause, "duplicate termination trigger ignored");
            } else {
                info!(cause = ?new_cause, "session termination requested");
                emit_fixture_cause(&new_cause);
                if let TerminationCause::WorkerSignal(signal) = &new_cause {
                    debug!(
                        ?signal,
                        "worker signal selected as authoritative termination cause"
                    );
                }
                match coordinator.begin(new_cause, grace, authoritative_scope) {
                    Ok(Some(new_observer)) => observer = Some(new_observer),
                    Ok(None) => {}
                    Err(outcome) => return Ok(SessionWaitResult::Graceful(outcome)),
                }
                emit_fixture_event("TimerArmed");
                info!(unit = %authoritative_scope.identity().unit_name, invocation_id = %authoritative_scope.identity().invocation_id, "graceful payload scope termination requested");
                info!(duration_ms = grace.as_millis(), "grace period armed");
            }
        }
        let deadline_expired = if fds[3].revents & libc::POLLIN != 0 {
            match coordinator.consume_deadline() {
                Ok(expired) => expired,
                Err(_) => {
                    return Ok(SessionWaitResult::Graceful(
                        coordinator.infrastructure(GracefulTerminationError::Timer),
                    ))
                }
            }
        } else {
            false
        };
        if deadline_expired {
            warn!("grace deadline expired");
            emit_fixture_event("DeadlineExpired");
            return Ok(SessionWaitResult::Graceful(coordinator.deadline_expired()));
        }
}
