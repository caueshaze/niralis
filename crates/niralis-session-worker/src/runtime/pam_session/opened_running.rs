{
            // Ownership of the validated boundary remains live for the entire
            // Running state. A3.2 will use it for bounded scope termination.
            info!(
                username = %canonical_username,
                session = %session.session.id,
                pid = child_report.child_pid,
                spawned_child_pid = child_report.child_pid,
                exec_probe_pid = child_report.process_identity.pid,
                sid = child_report.process_identity.sid,
                pgid = child_report.process_identity.pgid,
                sid_equals_pid = child_report.process_identity.sid == child_report.child_pid,
                pgid_equals_pid = child_report.process_identity.pgid == child_report.child_pid,
                uid = child_report.applied_credentials.uid,
                gid = child_report.applied_credentials.gid,
                supplementary_group_count = child_report.applied_credentials.supplementary_gids.len(),
                effective_capability_count = child_report.isolation_proof.capabilities.effective.len(),
                permitted_capability_count = child_report.isolation_proof.capabilities.permitted.len(),
                inheritable_capability_count = child_report.isolation_proof.capabilities.inheritable.len(),
                ambient_capability_count = child_report.isolation_proof.capabilities.ambient.len(),
                bounding_capability_count = child_report.isolation_proof.capabilities.bounding.len(),
                securebits = child_report.isolation_proof.securebits,
                no_new_privs = child_report.isolation_proof.no_new_privs,
                open_fd_count = child_report.isolation_proof.open_fds.len(),
                cwd_matches_home = child_report.runtime_environment.cwd == child_report.runtime_environment.home,
                runtime_session_type = %child_report.runtime_environment.session_type,
                probe_version = child_report.exec_probe_version,
                "worker session exec probe verified"
            );
            write_envelope(
                writer,
                WorkerResponse::Started {
                    session: session.clone(),
                    session_pid: child_report.child_pid,
                    session_pgid: child_report.process_identity.pgid,
                    fixture_version: child_report.exec_probe_version,
                    worker_id: worker_id.clone(),
                    logind_session_id: niralis_session::LogindSessionId::new(
                        logind.id.as_str().to_owned(),
                    )
                    .expect("validated logind id"),
                },
            )?;
            emit_fixture_event("Running");
            info!(username = %canonical_username, session = %session.session.id, pid = child_report.child_pid, "worker session started; PAM transaction remains open");
            let child_status = match wait_for_session(
                control_listener.as_ref(),
                child_runner.as_ref(),
                worker_id.clone(),
                child_report.child_pid,
                child_report.process_identity.pgid,
                authoritative_scope.as_ref(),
            ) {
                Ok(SessionWaitResult::Legacy(status)) => status,
                Ok(SessionWaitResult::Graceful(outcome)) => {
                    info!(?outcome, "graceful outcome received");
                    match crate::termination::consume_graceful_outcome(
                        outcome,
                        authoritative_scope.as_ref(),
                    ) {
                        crate::termination::GracefulFinalizationDecision::FinalizeCooperative(
                            proof,
                        ) => {
                            emit_fixture_event("BoundaryEmptyProofAccepted");
                            return finalize_session_after_empty_proof_with_vt_report(
                                authoritative_scope.as_mut(),
                                transaction,
                                &mut terminal,
                                proof,
                                false,
                                &worker_id,
                                &registration_nonce,
                            );
                        }
                        crate::termination::GracefulFinalizationDecision::NeedsEscalation(
                            crate::termination::EscalationEligibility::Eligible {
                                cause,
                                leader_exit,
                            },
                        ) => {
                            warn!("grace deadline expired; forced escalation required");
                            info!(unit = %authoritative_scope.identity().unit_name, invocation_id = %authoritative_scope.identity().invocation_id, "forced escalation eligibility confirmed");
                            emit_fixture_event("NeedsEscalation");
                            match wait_for_forced_cleanup(
                                ForcedWaitContext {
                                    listener: control_listener.as_ref(),
                                    child_runner: child_runner.as_ref(),
                                    worker_id: &worker_id,
                                    session_pid: child_report.child_pid,
                                    session_pgid: child_report.process_identity.pgid,
                                    authoritative_scope: authoritative_scope.as_ref(),
                                    expected_control_uid: internal_control_peer_uid(),
                                },
                                cause,
                                leader_exit,
                                configured_forced_cleanup_timeout(),
                            ) {
                                crate::termination::ForcedTerminationOutcome::BoundaryEmpty {
                                    proof,
                                    ..
                                } => {
                                    return finalize_session_after_empty_proof_with_vt_report(
                                        authoritative_scope.as_mut(),
                                        transaction,
                                        &mut terminal,
                                        proof,
                                        true,
                                        &worker_id,
                                        &registration_nonce,
                                    );
                                }
                                forced_outcome => {
                                    match &forced_outcome {
                                        crate::termination::ForcedTerminationOutcome::ForcedDeadlineExpired { .. } => {
                                            warn!(boundary_still_populated = "unknown", "SIGKILL was requested but the authoritative boundary did not become provably empty before the forced deadline");
                                        }
                                        crate::termination::ForcedTerminationOutcome::InfrastructureFailure { stage, .. } => {
                                            warn!(?stage, "forced termination infrastructure failed");
                                        }
                                        crate::termination::ForcedTerminationOutcome::RecoveryRequired { reason, .. } => {
                                            warn!(?reason, "forced termination requires recovery");
                                        }
                                        crate::termination::ForcedTerminationOutcome::BoundaryEmpty { .. } => unreachable!(),
                                    }
                                    warn!(?forced_outcome, "forced finalization requires recovery; PAM, VT and pin remain owned");
                                    emit_fixture_event("OwnershipRetained:Pam,Vt,Pin");
                                    wait_for_graceful_handoff();
                                }
                            }
                        }
                        decision => {
                            warn!(?decision, "graceful finalization requires recovery; PAM, VT and pin remain owned");
                            match decision {
                                crate::termination::GracefulFinalizationDecision::NeedsEscalation(
                                    crate::termination::EscalationEligibility::InfrastructureFailure { .. },
                                ) => emit_fixture_event("InfrastructureFailure"),
                                _ => emit_fixture_event("RecoveryRequired"),
                            }
                            emit_fixture_event("OwnershipRetained:Pam,Vt,Pin");
                            wait_for_graceful_handoff();
                        }
                    }
                }
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker failed while waiting for session child");
                    drop(transaction);
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            info!(username = %canonical_username, session = %session.session.id, ?child_status, "worker session child reaped");
            drop(transaction);
            info!(username = %canonical_username, session = %session.session.id, "worker PAM transaction closed");
            let _ = terminal.release();
            if child_status.success() {
                Ok(())
            } else {
                Err(SessionError::AuthenticatedSessionFailed)
            }
}
