{
            // The explicit graphical watchdog protects the launch proof only.
            // Once Started is emitted, the session may legitimately live for
            // hours or days and is governed by process supervision instead.
            let launch_watchdog_deadline = Instant::now() + watchdog;
            let pending_handoff = match child_runner.run_child_until_ready(
                SessionChildExpectation {
                    canonical_username: canonical_username.clone(),
                    session_id: session.session.id.clone(),
                    target_credentials: PrivilegeDropTarget::from(&credentials),
                    runtime,
                    terminal: Some(SessionChildTerminalContext {
                        seat: terminal.lease().seat().as_str().to_owned(),
                        vtnr: terminal.lease().vtnr().number(),
                        fd: 3,
                        device_major: 4,
                        device_minor: terminal.lease().vtnr().number(),
                    }),
                },
            ) {
                Ok(report) => report,
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker session child failed");
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::SessionChildFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            let child_report = pending_handoff.report().clone();
            launch_phase_gate.reached(WorkerLaunchPhase::PendingHandoffBeforeScope)?;
            if let Some(signal) = pending_worker_signal()? {
                emit_fixture_launch_signal(signal);
                info!("worker signal received during PendingExecHandoff; cancelling launch");
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            if Instant::now() >= launch_watchdog_deadline {
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            if !valid_terminal_proof(
                &child_report,
                terminal.lease().seat().as_str(),
                terminal.lease().vtnr().number(),
            ) {
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            match logind_resolver.resolve_by_pid(child_report.child_pid) {
                Ok(Some(child_identity))
                    if child_identity.id == logind.id
                        && valid_logind_identity(
                            &child_identity,
                            credentials.identity.uid,
                            expected_type,
                            &session.session.id,
                            terminal.lease().seat().as_str(),
                            terminal.lease().vtnr().number(),
                        ) => {}
                _ => {
                    let _ = pending_handoff.abort();
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::LogindFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            }
            if terminal
                .lease_mut()
                .activate(Duration::from_millis(1000))
                .is_err()
            {
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            // The post-exec probe remains blocked until its dedicated systemd
            // scope is created, independently re-resolved, and registered.
            if Instant::now() >= launch_watchdog_deadline {
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let requires_registration = payload_scope_manager.requires_supervisor_registration();
            if requires_registration && control_listener.is_none() {
                let _ = pending_handoff.abort();
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let logind_session_id =
                niralis_session::LogindSessionId::new(logind.id.as_str().to_owned())
                    .ok_or(SessionError::AuthenticatedSessionFailed)?;
            let mut authoritative_scope = match payload_scope_manager.prepare(
                pending_handoff.report(),
                pending_handoff.authoritative_pidfd(),
                credentials.identity.uid,
                &logind_session_id,
                std::process::id(),
                launcher_pid,
                launch_watchdog_deadline,
            ) {
                Ok(scope) => scope,
                Err(error) => {
                    warn!(
                        ?error,
                        "authoritative payload scope preparation failed before CommitExec"
                    );
                    let _ = pending_handoff.abort();
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::SessionChildFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            let registration_nonce = authoritative_scope.identity().invocation_id.clone();
    include!("opened_registration.rs")
}
