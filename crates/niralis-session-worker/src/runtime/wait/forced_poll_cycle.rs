{
    let mut fds = [
        libc::pollfd {
            fd: if leader_reaped { -1 } else { pidfd },
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: observer.as_raw_fd(),
            events: observer.poll_events(),
            revents: 0,
        },
        libc::pollfd {
            fd: signal_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: listener.map_or(-1, AsRawFd::as_raw_fd),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: supervisor_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: coordinator.timer_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return coordinator.infrastructure(
            ForcedTerminationStage::BoundaryObservation,
            ForcedTerminationError::Poll,
        );
    }

    // Reap and proof processing deliberately precede the forced deadline.
    if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 && !leader_reaped {
        let status = match child_runner.poll_child() {
            Ok(Some(status)) => status,
            Ok(None) | Err(_) => {
                return coordinator.infrastructure(
                    ForcedTerminationStage::LeaderReap,
                    ForcedTerminationError::LeaderReap,
                )
            }
        };
        let exit = LeaderExit::from_status(status);
        if exit == LeaderExit::KilledBySignal(libc::SIGKILL) {
            info!(status = "SIGKILL", "authoritative leader killed");
            emit_fixture_event("LeaderKilledBySigkill");
        } else {
            info!(?exit, "authoritative session leader reaped during forced cleanup");
        }
        coordinator.record_leader_exit(exit);
        leader_reaped = true;
        if let Some(outcome) = try_forced_empty_proof(authoritative_scope, &mut coordinator) {
            return outcome;
        }
    }

    if fds[1].revents != 0 {
        if observer.consume_wakeup().is_err() {
            return coordinator.infrastructure(
                ForcedTerminationStage::BoundaryObservation,
                ForcedTerminationError::BoundaryObserver,
            );
        }
        if let Some(outcome) = try_forced_empty_proof(authoritative_scope, &mut coordinator) {
            return outcome;
        }
    }

    if fds[2].revents & libc::POLLIN != 0 {
        loop {
            let signal = match crate::termination::read_signal_fd(signal_fd) {
                Ok(Some(signal)) => signal,
                Ok(None) => break,
                Err(_) => {
                    return coordinator.infrastructure(
                        ForcedTerminationStage::BoundaryObservation,
                        ForcedTerminationError::Signal,
                    )
                }
            };
            if WorkerTerminationSignal::from_raw(signal).is_none() {
                return coordinator.infrastructure(
                    ForcedTerminationStage::BoundaryObservation,
                    ForcedTerminationError::Signal,
                );
            }
            info!(signal, "duplicate termination trigger ignored during forced cleanup");
        }
    }

    if fds[3].revents & libc::POLLIN != 0 {
        let Some(listener) = listener else {
            return coordinator.infrastructure(
                ForcedTerminationStage::BoundaryObservation,
                ForcedTerminationError::Control,
            );
        };
        match listener.accept() {
            Ok((mut stream, _)) if peer_has_uid(&stream, expected_control_uid) => {
                let request = match read_control_request(&mut stream) {
                    Ok(request) => request,
                    Err(_) => {
                        return coordinator.infrastructure(
                            ForcedTerminationStage::BoundaryObservation,
                            ForcedTerminationError::Control,
                        )
                    }
                };
                match request.message {
                    WorkerControlRequest::Terminate {
                        worker_id: requested_worker_id,
                        expected_worker_pid,
                        expected_session_pid,
                        expected_session_pgid,
                    } if request.version == WORKER_CONTROL_PROTOCOL_VERSION
                        && requested_worker_id == worker_id
                        && expected_worker_pid == std::process::id()
                        && expected_session_pid == session_pid
                        && expected_session_pgid == session_pgid =>
                    {
                        info!("duplicate authenticated terminate ignored during forced cleanup");
                    }
                    _ => {
                        return coordinator.infrastructure(
                            ForcedTerminationStage::BoundaryObservation,
                            ForcedTerminationError::Control,
                        )
                    }
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                return coordinator.infrastructure(
                    ForcedTerminationStage::BoundaryObservation,
                    ForcedTerminationError::Control,
                )
            }
        }
    }

    if fds[3].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        || fds[4].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
    {
        info!("duplicate supervisor disconnect ignored during forced cleanup");
    }

    let deadline_expired = if fds[5].revents & libc::POLLIN != 0 {
        match coordinator.consume_deadline() {
            Ok(expired) => expired,
            Err(_) => {
                return coordinator.infrastructure(
                    ForcedTerminationStage::BoundaryObservation,
                    ForcedTerminationError::Timer,
                )
            }
        }
    } else {
        false
    };
    if deadline_expired {
        // A proof that becomes available in the same cycle wins over timeout.
        if let Some(outcome) = try_forced_empty_proof(authoritative_scope, &mut coordinator) {
            return outcome;
        }
        warn!(boundary_still_populated = "unknown", "forced cleanup deadline expired");
        emit_fixture_event("ForcedDeadlineExpired");
        return coordinator.deadline_expired();
    }
}
