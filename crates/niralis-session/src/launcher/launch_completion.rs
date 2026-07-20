impl WorkerSessionLauncher {
    fn start_worker(
        &self,
        mut request: WorkerRequest,
        expected: StartedSession,
        install_control: bool,
    ) -> Result<(StartedSession, RuntimeSessionId), SessionError> {
        let (control_dir, control_path, worker_id) = create_control_endpoint()?;
        let requires_pending_lifecycle = matches!(&request, WorkerRequest::PamSession { .. });
        if install_control {
            install_control_request(&mut request, control_path.clone(), worker_id.clone());
        }
        let mut seat_reservation = if requires_pending_lifecycle {
            let previous_vt = self.supervisor.reserve_seat(&worker_id)?;
            Some((
                SeatReservationGuard {
                    supervisor: self.supervisor.clone(),
                    worker_id: worker_id.clone(),
                    armed: true,
                },
                previous_vt,
            ))
        } else {
            None
        };
        let deadline = Instant::now() + self.timeout;
        let mut attempt =
            WorkerAttempt::spawn(&self.worker_path, &self.worker_environment, request)?;
        let worker_pid = attempt.child_id();
        let mut pending_guard = if requires_pending_lifecycle {
            self.supervisor.begin_pending(
                &worker_id,
                worker_pid,
                std::process::id(),
                expected.clone(),
                attempt.shared_child(),
                seat_reservation
                    .as_ref()
                    .expect("PAM launch seat reservation")
                    .1
                    .clone(),
            )?;
            seat_reservation
                .as_mut()
                .expect("PAM launch seat reservation")
                .0
                .consume();
            Some(PendingSupervisorGuard {
                supervisor: self.supervisor.clone(),
                worker_id: worker_id.clone(),
                expected_clean: false,
                worker_exit_status: None,
            })
        } else {
            None
        };
        let writer_result = attempt.wait_writer(deadline);
        let (response_result, phase) =
            self.wait_launch_response(&mut attempt, deadline, worker_id.clone(), worker_pid)?;
        let started_response = response_result
            .as_ref()
            .ok()
            .and_then(|response| match &response.message {
                WorkerResponse::Started { .. } => Some(()),
                _ => None,
            })
            .is_some();
        if started_response {
            writer_result?;
            let response = response_result?;
            match response.message {
                WorkerResponse::Started {
                    session,
                    session_pid,
                    session_pgid,
                    fixture_version,
                    worker_id: started_worker_id,
                    logind_session_id,
                } if session == expected
                    && matches!(fixture_version, 1 | 2)
                    && (started_worker_id == worker_id || started_worker_id.is_empty())
                    && session_pgid == session_pid =>
                {
                    let (payload_scope, registration_nonce) = if let PendingLaunchPhase::ScopeRegistered {
                        identity,
                        registration_nonce,
                    } = &phase
                    {
                        debug!(unit = %identity.unit_name, nonce_len = registration_nonce.len(), "promoting pre-Started payload scope registration");
                        if identity.logind_session_id != logind_session_id {
                            return Err(SessionError::WorkerProtocolFailed);
                        }
                        (identity.clone(), registration_nonce.clone())
                    } else {
                        return Err(SessionError::WorkerProtocolFailed);
                    };
                    if !attempt.is_alive()? {
                        return Err(SessionError::WorkerExitedAfterStart);
                    }
                    attempt.finish();
                    let supervisor_channel = attempt.take_supervisor_channel();
                    let child = attempt.shared_child();
                    let runtime_id = self.supervisor.register(
                        child,
                        supervisor_channel,
                        expected.clone(),
                        session_pid,
                        session_pgid,
                        worker_id,
                        logind_session_id,
                        payload_scope,
                        registration_nonce,
                        control_path,
                        control_dir,
                    )?;
                    attempt.retain_by_supervisor();
                    return Ok((expected, runtime_id));
                }
                WorkerResponse::Started { .. } => return Err(SessionError::WorkerProtocolFailed),
                _ => unreachable!(),
            }
        }
        let status_result = if response_result.is_ok() {
            attempt.wait_child(deadline)
        } else {
            Ok(None)
        };

        let writer_failed = matches!(writer_result, Err(SessionError::WorkerIoFailed));
        let reader_failed = matches!(response_result, Err(SessionError::WorkerIoFailed));
        let status_failed = matches!(status_result, Err(SessionError::WorkerIoFailed));
        if writer_failed || reader_failed || status_failed {
            attempt.kill_and_reap();
        }
        attempt.finish();

        if response_result.is_err() || status_result.is_err() {
            if let Some(guard) = pending_guard.take() {
                let recovery = guard.complete();
                return Err(if recovery.is_ok() {
                    SessionError::WorkerDiedAndWasRecovered
                } else {
                    SessionError::WorkerRecoveryIncomplete
                });
            }
            return Err(response_result
                .err()
                .or_else(|| status_result.err())
                .unwrap_or(SessionError::WorkerProtocolFailed));
        }
        if !writer_failed {
            if let Err(error) = writer_result {
            if let Some(guard) = pending_guard.take() {
                return Err(if guard.complete().is_ok() {
                    error
                } else {
                    SessionError::WorkerRecoveryIncomplete
                });
            }
            return Err(error);
            }
        }
        let response = response_result?;
        let status = status_result?.ok_or(SessionError::WorkerProtocolFailed)?;
        debug!(?status, "session worker exited");
        if let Some(guard) = pending_guard.as_mut() {
            guard.mark_expected_clean(status);
        }
        if let Some(guard) = pending_guard.take() {
            guard.complete()?;
        }
        map_response(response, status, expected)
            .map(|session| (session, RuntimeSessionId::new("completed".to_owned())))
    }
}
