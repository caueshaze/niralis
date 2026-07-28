impl WorkerSessionLauncher {
    fn start_worker(
        &self,
        mut request: WorkerRequest,
        expected: StartedSession,
        install_control: bool,
    ) -> Result<(StartedSession, RuntimeSessionId), SessionError> {
        let (control_dir, control_path, worker_id) = create_control_endpoint()?;
        let requires_pending_lifecycle = matches!(&request, WorkerRequest::PamSession(_));
        let registered_control_path = control_path.clone();
        if install_control {
            install_control_request(&mut request, control_path.clone(), worker_id.clone());
        }
        let mut seat_reservation = if requires_pending_lifecycle {
            let lease = self.supervisor.reserve_seat(&worker_id)?;
            Some((SeatReservationGuard {
                supervisor: self.supervisor.clone(),
                lease: Some(lease),
            },))
        } else {
            None
        };
        let deadline = Instant::now() + self.timeout;
        let transaction_generation = seat_reservation
            .as_ref()
            .and_then(|guard| guard.0.lease.as_ref())
            .map_or(0, |lease| lease.generation());
        let transaction_attempt_id = seat_reservation
            .as_ref()
            .and_then(|guard| guard.0.lease.as_ref())
            .map_or(0, |lease| lease.attempt_id());
        if requires_pending_lifecycle {
            if let WorkerRequest::PamSession(request) = &mut request {
                *request.transaction = crate::WorkerTransactionIdentity {
                    transaction_id: worker_id.clone(),
                    admission_attempt_id: transaction_attempt_id,
                    lifecycle_id: worker_id.clone(),
                    seat: "seat0".to_owned(),
                    seat_generation: transaction_generation,
                    stage: "reserved".to_owned(),
                };
            }
        }
        let connection_binding = match &request {
            WorkerRequest::PamSession(request) => request.connection.clone(),
            WorkerRequest::PrepareSession { .. } => None,
        };
        let mut attempt = WorkerAttempt::spawn(
            &self.worker_path,
            &self.worker_environment,
            request,
            #[cfg(any(
                test,
                feature = "integration-test-control",
                feature = "supervisor-test-fixtures"
            ))]
            self.fixture_supervisor_transport,
            #[cfg(not(any(
                test,
                feature = "integration-test-control",
                feature = "supervisor-test-fixtures"
            )))]
            false,
        )?;
        let worker_pid = attempt.child_id();
        let mut transaction = if requires_pending_lifecycle {
            let lease = seat_reservation
                .as_mut()
                .expect("PAM launch seat reservation")
                .0
                .lease
                .take()
                .expect("seat reservation owns admission lease");
            let identity = connection_binding
                .map(|binding| {
                    login_transaction::GreeterConnectionIdentity::from_binding(
                        binding,
                        worker_id.clone(),
                    )
                })
                .unwrap_or_else(|| {
                    login_transaction::GreeterConnectionIdentity::private(worker_id.clone())
                });
            let tx = login_transaction::LoginTransaction::from_admission(
                lease,
                identity,
                expected.session.id.clone(),
                deadline,
            );
            let backend = match tx.attach_backend(
                login_transaction::UnboundLocalLoginBackend::private(),
                login_transaction::ValidatedWorkerChannel::private(worker_id.clone(), worker_pid),
            ) {
                Ok(backend) => backend,
                Err(error) => {
                    let (error, mut transaction) = *error;
                    let lease = transaction
                        .take_lease()
                        .map_err(|_| SessionError::WorkerProtocolFailed)?;
                    seat_reservation
                        .as_mut()
                        .expect("PAM launch seat reservation")
                        .0
                        .lease = Some(lease);
                    return Err(error);
                }
            };
            let authenticated = match backend.authentication() {
                Ok(permit) => permit.authenticated(),
                Err(error) => {
                    let (error, mut backend) = *error;
                    let lease = backend
                        .take_lease()
                        .map_err(|_| SessionError::WorkerProtocolFailed)?;
                    seat_reservation
                        .as_mut()
                        .expect("PAM launch seat reservation")
                        .0
                        .lease = Some(lease);
                    return Err(error);
                }
            };
            let prepared = authenticated.prepare();
            if !prepared.validate_expected(&worker_id, &expected.session.id) {
                let (_, lease) = prepared
                    .take_admission_lease()
                    .map_err(|_| SessionError::WorkerProtocolFailed)?;
                seat_reservation
                    .as_mut()
                    .expect("PAM launch seat reservation")
                    .0
                    .lease = Some(lease);
                return Err(SessionError::WorkerProtocolFailed);
            }
            Some(prepared)
        } else {
            None
        };
        let mut pending_guard = if requires_pending_lifecycle {
            let (prepared, lease) = transaction
                .take()
                .expect("PAM launch transaction")
                .take_admission_lease()?;
            let pending_lease = self.supervisor.begin_pending(
                lease,
                worker_pid,
                std::process::id(),
                expected.clone(),
                attempt.shared_child(),
            )?;
            seat_reservation
                .as_mut()
                .expect("PAM launch seat reservation")
                .0
                .consume();
            Some(PendingSupervisorGuard {
                supervisor: self.supervisor.clone(),
                transaction: Some(prepared.pending(pending_lease)),
                expected_clean: false,
                worker_exit_status: None,
            })
        } else {
            None
        };
        let writer_result = attempt.wait_writer(deadline);
        let (response_result, phase) = self.wait_launch_response(
            &mut attempt,
            deadline,
            worker_id.clone(),
            worker_pid,
            transaction_generation,
            transaction_attempt_id,
        )?;
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
                    transaction,
                } if session == expected
                    && matches!(fixture_version, 1 | 2)
                    && (started_worker_id == worker_id || started_worker_id.is_empty())
                    && session_pgid == session_pid
                    && valid_transaction(
                        &transaction,
                        &worker_id,
                        transaction_generation,
                        transaction_attempt_id,
                        "started",
                    ) =>
                {
                    let (payload_scope, registration_nonce) =
                        if let PendingLaunchPhase::ScopeRegistered {
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
                    #[cfg(any(
                        test,
                        feature = "integration-test-control",
                        feature = "supervisor-test-fixtures"
                    ))]
                    let fixture_supervisor_transport = attempt.take_fixture_supervisor_transport();
                    let child = attempt.shared_child();
                    let runtime_id = self.supervisor.register(
                        pending_guard
                            .as_mut()
                            .expect("PAM launch owns pending login transaction")
                            .take_transaction(),
                        child,
                        supervisor_channel,
                        #[cfg(any(
                            test,
                            feature = "integration-test-control",
                            feature = "supervisor-test-fixtures"
                        ))]
                        fixture_supervisor_transport,
                        #[cfg(any(
                            test,
                            feature = "integration-test-control",
                            feature = "supervisor-test-fixtures"
                        ))]
                        self.fixture_inherited_supervisor_control,
                        expected.clone(),
                        session_pid,
                        session_pgid,
                        worker_id,
                        logind_session_id,
                        payload_scope,
                        registration_nonce,
                        registered_control_path,
                        control_dir,
                    )?;
                    pending_guard.take();
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
