{
            if let Some(signal) = pending_worker_signal()? {
                emit_fixture_launch_signal(signal);
                info!("worker signal received during PendingExecHandoff; CommitExec cancelled");
                let scope_identity = authoritative_scope.identity().clone();
                let probe_reaped = pending_handoff.abort().is_ok();
                let local_cleanup_succeeded = probe_reaped
                    && authoritative_scope
                        .cleanup_preserving_pin(launch_watchdog_deadline)
                        .is_ok();
                if requires_registration {
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
                } else if authoritative_scope.release_pin().is_err() {
                    wait_for_prestarted_recovery(authoritative_scope, transaction, terminal);
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
            let child_report = match pending_handoff.commit_exec() {
                Ok(report) => report,
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker failed to commit the post-exec session handoff");
                    let scope_identity = authoritative_scope.identity().clone();
                    let local_cleanup_succeeded = authoritative_scope
                        .cleanup(launch_watchdog_deadline)
                        .is_ok();
                    if !local_cleanup_succeeded {
                        warn!("payload scope cleanup after CommitExec failure failed");
                    }
                    if requires_registration {
                        let _ = request_payload_scope_release(
                            writer,
                            &worker_id,
                            &registration_nonce,
                            &scope_identity,
                            local_cleanup_succeeded,
                            launch_watchdog_deadline,
                        );
                    }
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::CommitFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            // The probe deliberately remains in niralis_t while it is blocked.
            // It applies the PAM-provided pending exec context only after
            // CommitExec, immediately before execve(2). Therefore the context
            // proof belongs here, after the status pipe has proved that final
            // exec succeeded, but before Started can be emitted.
            if let Some(expected_context) = &selinux_exec_context {
                let context_error = match selinux_context_manager
                    .context_for_pid(child_report.child_pid)
                {
                    Ok(observed_context) if expected_context.matches(&observed_context) => None,
                    Ok(observed_context) => {
                        warn!(
                            stage = "post_exec_selinux_context",
                            pid = child_report.child_pid,
                            expected_context = %expected_context.as_str(),
                            observed_context = %observed_context.as_str(),
                            "final session process SELinux context did not match the PAM context"
                        );
                        Some(())
                    }
                    Err(error) => {
                        warn!(
                            stage = "post_exec_selinux_context",
                            pid = child_report.child_pid,
                            ?error,
                            "could not read the final session process SELinux context"
                        );
                        Some(())
                    }
                };
                if context_error.is_some() {
                    let scope_identity = authoritative_scope.identity().clone();
                    if let Err(error) = child_runner.terminate(SESSION_TERMINATION_GRACE) {
                        warn!(?error, "final session process cleanup after SELinux context verification failure failed");
                    }
                    let local_cleanup_succeeded = authoritative_scope
                        .cleanup(launch_watchdog_deadline)
                        .is_ok();
                    if !local_cleanup_succeeded {
                        warn!("payload scope cleanup after SELinux context verification failure failed");
                    }
                    if requires_registration {
                        let _ = request_payload_scope_release(
                            writer,
                            &worker_id,
                            &registration_nonce,
                            &scope_identity,
                            local_cleanup_succeeded,
                            launch_watchdog_deadline,
                        );
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
            }
    include!("opened_running.rs")
}
