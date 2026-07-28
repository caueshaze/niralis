impl WorkerSessionLauncher {
    #[allow(clippy::too_many_arguments)]
    fn wait_launch_response(
        &self,
        attempt: &mut WorkerAttempt,
        deadline: Instant,
        worker_id: String,
        worker_pid: u32,
        transaction_generation: u64,
        transaction_attempt_id: u64,
        conversation: Option<std::sync::Arc<dyn crate::PamConversationTransport>>,
        mut pam_authority: Option<&mut crate::PamConversationAuthority>,
    ) -> Result<
        (
            Result<crate::WorkerEnvelope<WorkerResponse>, SessionError>,
            PendingLaunchPhase,
        ),
        SessionError,
    > {
        let mut phase = PendingLaunchPhase::Spawned;
        let mut control_transaction = None;
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
                            transaction,
                        },
                    ..
                }) => {
                    if !matches!(phase, PendingLaunchPhase::Spawned)
                        || event_worker_id != worker_id
                        || !valid_transaction(&transaction, &worker_id, transaction_generation, transaction_attempt_id, "preparing")
                    {
                        break Err(SessionError::WorkerProtocolFailed);
                    }
                    phase = PendingLaunchPhase::Preparing;
                }
                Ok(WorkerEnvelope {
                    message:
                        WorkerResponse::PayloadScopePrepared {
                            worker_id: event_worker_id,
                            transaction,
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
                        || !valid_transaction(&transaction, &worker_id, transaction_generation, transaction_attempt_id, "scope_prepared")
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
                    control_transaction = Some(transaction.clone());
                    if attempt
                        .send_supervisor_control_request(WorkerControlRequest::PayloadScopeRegistered {
                            transaction: crate::ControlTransactionIdentity::from_worker(
                                &transaction,
                                "scope_registered",
                                1,
                            ),
                            worker_id: worker_id.clone(),
                            expected_worker_pid: worker_pid,
                            registration_nonce,
                        })
                    .is_err()
                    {
                        break Err(SessionError::WorkerIoFailed);
                    }
                    self.supervisor
                        .mark_payload_registered(&worker_id, worker_pid)?;
                }
                Ok(WorkerEnvelope {
                    message: WorkerResponse::PamPrompt {
                        worker_id: event_worker_id,
                        expected_worker_pid,
                        transaction,
                        prompt,
                    },
                    ..
                }) => {
                    if !matches!(phase, PendingLaunchPhase::Preparing) {
                        break Err(SessionError::WorkerProtocolFailed);
                    }
                    if let Err(error) = forward_pam_prompt(
                        attempt, event_worker_id, expected_worker_pid, transaction, prompt,
                        &worker_id, worker_pid, transaction_generation, transaction_attempt_id,
                        conversation.as_ref(),
                        pam_authority.as_deref_mut(),
                    ) {
                        break Err(error);
                    }
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
                    let request = match attempt.read_supervisor_control_request() {
                        Ok(request) if request.version == crate::WORKER_CONTROL_PROTOCOL_VERSION => {
                            request.message
                        }
                        _ => break Err(SessionError::WorkerProtocolFailed),
                    };
                    let transaction = match control_transaction.as_ref() {
                        Some(transaction) => transaction,
                        None => break Err(SessionError::WorkerProtocolFailed),
                    };
                    let (release_nonce, local_cleanup_succeeded) = match request {
                        WorkerControlRequest::PayloadScopeReleaseRequested {
                            transaction: request_transaction,
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
                            && request_transaction.matches_worker(
                                transaction,
                                "scope_release_requested",
                                2,
                            )
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
                                transaction: crate::ControlTransactionIdentity::from_worker(
                                    transaction,
                                    "scope_released",
                                    3,
                                ),
                                worker_id: worker_id.clone(),
                                expected_worker_pid: worker_pid,
                                registration_nonce,
                                release_nonce,
                            }
                        }
                        crate::ScopeReleaseVerification::RecoveryRequired(reason) => {
                            debug!(?reason, unit = %identity.unit_name, "payload scope cleanup could not be proven; lifecycle marked recovery required");
                            WorkerControlRequest::PayloadScopeRecoveryRequired {
                                transaction: crate::ControlTransactionIdentity::from_worker(
                                    transaction,
                                    "scope_recovery_required",
                                    3,
                                ),
                                worker_id: worker_id.clone(),
                                expected_worker_pid: worker_pid,
                                registration_nonce,
                                release_nonce,
                                reason,
                            }
                        }
                    };
                    if attempt.send_supervisor_control_request(response).is_err() {
                        break Err(SessionError::WorkerIoFailed);
                    }
                }
                terminal => break terminal,
            }
        };
        Ok((response_result, phase))
    }

}

fn valid_transaction(
    identity: &crate::WorkerTransactionIdentity,
    worker_id: &str,
    generation: u64,
    attempt_id: u64,
    stage: &str,
) -> bool {
    identity.transaction_id == worker_id
        && identity.lifecycle_id == worker_id
        && identity.admission_attempt_id == attempt_id
        && identity.seat == "seat0"
        && identity.seat_generation == generation
        && identity.stage == stage
}
