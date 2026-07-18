impl WorkerSessionLauncher {
    fn wait_launch_response(
        &self,
        attempt: &mut WorkerAttempt,
        deadline: Instant,
        worker_id: String,
        worker_pid: u32,
    ) -> Result<
        (
            Result<crate::WorkerEnvelope<WorkerResponse>, SessionError>,
            PendingLaunchPhase,
        ),
        SessionError,
    > {
        let mut phase = PendingLaunchPhase::Spawned;
        let response_result = loop {
            let event = attempt.wait_reader(deadline);
            match event {
                Ok(response) if response.version != crate::WORKER_PROTOCOL_VERSION => {
                    break Err(SessionError::WorkerProtocolFailed);
                }
                Ok(WorkerEnvelope {
                    message:
                        WorkerResponse::Preparing {
                            worker_id: event_worker_id,
                        },
                    ..
                }) => {
                    if !matches!(phase, PendingLaunchPhase::Spawned) || event_worker_id != worker_id
                    {
                        break Err(SessionError::WorkerProtocolFailed);
                    }
                    phase = PendingLaunchPhase::Preparing;
                }
                Ok(WorkerEnvelope {
                    message:
                        WorkerResponse::PayloadScopePrepared {
                            worker_id: event_worker_id,
                            expected_worker_pid,
                            session_pid,
                            registration_nonce,
                            scope_identity,
                        },
                    ..
                }) => {
                    if !matches!(phase, PendingLaunchPhase::Preparing)
                        || event_worker_id != worker_id
                        || expected_worker_pid != worker_pid
                        || session_pid == 0
                        || registration_nonce.is_empty()
                        || registration_nonce.len() > 128
                        || !scope_identity.validate()
                    {
                        break Err(SessionError::WorkerProtocolFailed);
                    }
                    self.supervisor.record_prepared_scope(
                        &worker_id,
                        worker_pid,
                        session_pid,
                        scope_identity.clone(),
                        registration_nonce.clone(),
                    )?;
                    // Persisted before acknowledging it. No registry lock is
                    // held while performing socket I/O.
                    phase = PendingLaunchPhase::ScopeRegistered {
                        identity: scope_identity,
                        registration_nonce: registration_nonce.clone(),
                    };
                    if write_control_request(
                        attempt.supervisor_channel_mut(),
                        WorkerControlRequest::PayloadScopeRegistered {
                            worker_id: worker_id.clone(),
                            expected_worker_pid: worker_pid,
                            registration_nonce,
                        },
                    )
                    .is_err()
                    {
                        break Err(SessionError::WorkerIoFailed);
                    }
                    self.supervisor
                        .mark_payload_registered(&worker_id, worker_pid)?;
                }
                Ok(WorkerEnvelope {
                    message:
                        WorkerResponse::PayloadScopeReleaseReady {
                            worker_id: event_worker_id,
                        },
                    ..
                }) => {
                    let (identity, registration_nonce) = match &phase {
                        PendingLaunchPhase::ScopeRegistered {
                            identity,
                            registration_nonce,
                        } if event_worker_id == worker_id => {
                            (identity.clone(), registration_nonce.clone())
                        }
                        _ => break Err(SessionError::WorkerProtocolFailed),
                    };
                    let request =
                        match crate::read_control_request(attempt.supervisor_channel_mut()) {
                            Ok(request)
                                if request.version == crate::WORKER_CONTROL_PROTOCOL_VERSION =>
                            {
                                request.message
                            }
                            _ => break Err(SessionError::WorkerProtocolFailed),
                        };
                    let (release_nonce, local_cleanup_succeeded) = match request {
                        WorkerControlRequest::PayloadScopeReleaseRequested {
                            worker_id: requested_worker_id,
                            expected_worker_pid,
                            registration_nonce: requested_registration_nonce,
                            release_nonce,
                            scope_identity,
                            local_cleanup_succeeded,
                        } if requested_worker_id == worker_id
                            && expected_worker_pid == worker_pid
                            && requested_registration_nonce == registration_nonce
                            && scope_identity == identity
                            && !release_nonce.is_empty()
                            && release_nonce.len() <= 128 =>
                        {
                            (release_nonce, local_cleanup_succeeded)
                        }
                        _ => break Err(SessionError::WorkerProtocolFailed),
                    };
                    debug!(
                        local_cleanup_succeeded,
                        "payload scope release requested; supervisor verifying registered scope"
                    );
                    let token = self.supervisor.begin_release(ReleaseRequest {
                        worker_id: worker_id.clone(),
                        worker_pid,
                        registration_nonce: registration_nonce.clone(),
                        release_nonce: release_nonce.clone(),
                        identity: identity.clone(),
                    })?;
                    let verification = self.release_verifier.verify(&identity, deadline);
                    self.supervisor
                        .complete_release(token, verification.clone())?;
                    let response = match verification {
                        crate::ScopeReleaseVerification::Released => {
                            debug!(unit = %identity.unit_name, "payload scope release acknowledged");
                            WorkerControlRequest::PayloadScopeReleased {
                                worker_id: worker_id.clone(),
                                expected_worker_pid: worker_pid,
                                registration_nonce,
                                release_nonce,
                            }
                        }
                        crate::ScopeReleaseVerification::RecoveryRequired(reason) => {
                            debug!(?reason, unit = %identity.unit_name, "payload scope cleanup could not be proven; lifecycle marked recovery required");
                            WorkerControlRequest::PayloadScopeRecoveryRequired {
                                worker_id: worker_id.clone(),
                                expected_worker_pid: worker_pid,
                                registration_nonce,
                                release_nonce,
                                reason,
                            }
                        }
                    };
                    if write_control_request(attempt.supervisor_channel_mut(), response).is_err() {
                        break Err(SessionError::WorkerIoFailed);
                    }
                }
                terminal => break terminal,
            }
        };
        Ok((response_result, phase))
    }

}
