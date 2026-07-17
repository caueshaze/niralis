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
        let deadline = Instant::now() + self.timeout;
        let mut attempt =
            WorkerAttempt::spawn(&self.worker_path, &self.worker_environment, request)?;
        let worker_pid = attempt.child_id();
        let _pending_guard = if requires_pending_lifecycle {
            self.supervisor.begin_pending(&worker_id, worker_pid)?;
            Some(PendingSupervisorGuard {
                supervisor: self.supervisor.clone(),
                worker_id: worker_id.clone(),
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
                    let payload_scope = if let PendingLaunchPhase::ScopeRegistered {
                        identity,
                        registration_nonce,
                    } = &phase
                    {
                        debug!(unit = %identity.unit_name, nonce_len = registration_nonce.len(), "promoting pre-Started payload scope registration");
                        if identity.logind_session_id != logind_session_id {
                            return Err(SessionError::WorkerProtocolFailed);
                        }
                        identity.clone()
                    } else {
                        return Err(SessionError::WorkerProtocolFailed);
                    };
                    if !attempt.is_alive()? {
                        return Err(SessionError::WorkerExitedAfterStart);
                    }
                    attempt.finish();
                    let supervisor_channel = attempt.take_supervisor_channel();
                    let child = attempt.take_child();
                    let runtime_id = self.supervisor.register(
                        child,
                        supervisor_channel,
                        expected.clone(),
                        session_pid,
                        session_pgid,
                        worker_id,
                        logind_session_id,
                        payload_scope,
                        control_path,
                        control_dir,
                    )?;
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

        if !writer_failed {
            writer_result?;
        }
        let response = response_result?;
        let status = status_result?.ok_or(SessionError::WorkerProtocolFailed)?;
        debug!(?status, "session worker exited");
        map_response(response, status, expected)
            .map(|session| (session, RuntimeSessionId::new("completed".to_owned())))
    }
}
