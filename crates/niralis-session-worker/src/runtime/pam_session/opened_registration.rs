{
            if requires_registration {
                if let Err(error) = write_envelope(
                    writer,
                    WorkerResponse::PayloadScopePrepared {
                        worker_id: worker_id.clone(),
                        expected_worker_pid: std::process::id(),
                        session_pid: pending_handoff.report().child_pid,
                        registration_nonce: registration_nonce.clone(),
                        scope_identity: authoritative_scope.identity().clone(),
                    },
                ) {
                    let _ = pending_handoff.abort();
                    if let Err(cleanup_error) =
                        authoritative_scope.cleanup(launch_watchdog_deadline)
                    {
                        warn!(
                            ?cleanup_error,
                            "payload scope cleanup after registration transport failure failed"
                        );
                    }
                    drop(transaction);
                    return Err(error);
                }
                emit_fixture_event("PayloadScopePreparedSent");
                info!(unit = %authoritative_scope.identity().unit_name, "payload scope prepared for supervisor registration");
                launch_phase_gate.reached(WorkerLaunchPhase::ScopePinnedBeforeAck)?;
                if let Err(error) = await_payload_scope_ack(
                    &worker_id,
                    std::process::id(),
                    &registration_nonce,
                    launch_watchdog_deadline,
                ) {
                    warn!(?error, "payload scope registration acknowledgement failed");
                    let scope_identity = authoritative_scope.identity().clone();
                    let probe_reaped = pending_handoff.abort().is_ok();
                    let local_cleanup_succeeded = probe_reaped
                        && authoritative_scope
                            .cleanup_preserving_pin(launch_watchdog_deadline)
                            .is_ok();
                    if !local_cleanup_succeeded {
                        warn!(probe_reaped, "payload scope pre-commit cleanup failed");
                    }
                    let release = request_payload_scope_release(
                        writer,
                        &worker_id,
                        &registration_nonce,
                        &scope_identity,
                        local_cleanup_succeeded,
                        launch_watchdog_deadline,
                    );
                    match release {
                        Ok(PayloadScopeReleaseOutcome::Released) => {
                            emit_fixture_event("PayloadScopeReleasedReceived");
                            if authoritative_scope.release_pin().is_err() {
                                wait_for_prestarted_recovery(
                                    authoritative_scope,
                                    transaction,
                                    terminal,
                                );
                            }
                        }
                        Ok(PayloadScopeReleaseOutcome::RecoveryRequired) | Err(_) => {
                            emit_fixture_event("PayloadScopeRecoveryRequiredReceived");
                            wait_for_prestarted_recovery(
                                authoritative_scope,
                                transaction,
                                terminal,
                            );
                        }
                    }
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::SessionChildFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
                info!(
                    "authenticated payload scope registration acknowledged; CommitExec authorized"
                );
                emit_fixture_event("PayloadScopeAcknowledged");
                launch_phase_gate.reached(WorkerLaunchPhase::AckReceivedBeforeCommitExec)?;
            }
    include!("opened_commit.rs")
}
