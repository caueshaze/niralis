{
            let pam_environment = match transaction.session_environment() {
                Ok(environment) => environment,
                Err(error) => {
                    warn!(
                        username = %canonical_username,
                        session = %session.session.id,
                        ?error,
                        "worker failed to extract PAM graphical runtime environment"
                    );
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::RuntimeEnvironmentFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            info!(username = %canonical_username, session = %session.session.id, "worker PAM session opened");
            let logind = match logind_resolver.resolve_by_pid(std::process::id()) {
                Ok(Some(identity))
                    if valid_logind_identity(
                        &identity,
                        credentials.identity.uid,
                        expected_type,
                        &session.session.id,
                        terminal.lease().seat().as_str(),
                        terminal.lease().vtnr().number(),
                    ) =>
                {
                    identity
                }
                _ => {
                    drop(transaction);
                    write_envelope(
                        writer,
                        WorkerResponse::SessionFailed {
                            code: WorkerSessionFailureCode::LogindFailed,
                        },
                    )?;
                    return Err(SessionError::AuthenticatedSessionFailed);
                }
            };
            if pam_environment.session_id != logind.id.as_str() {
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::LogindSessionIdMismatch,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let runtime_dir = PathBuf::from(std::ffi::OsString::from_vec(
                pam_environment.runtime_dir.bytes.clone(),
            ));
            if runtime_dir_validator
                .validate(&runtime_dir, credentials.identity.uid)
                .is_err()
            {
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::RuntimeDirectoryInvalid,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let selinux_exec_context = match selinux_context_manager.capture_pending() {
                Ok(context) => context,
                Err(error) => {
                    warn!(
                        stage = "capture_pam_selinux_exec_context",
                        ?error,
                        "worker could not capture the PAM SELinux exec context"
                    );
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
            if selinux_exec_context.is_some() && selinux_context_manager.clear_pending().is_err() {
                warn!(
                    stage = "clear_pam_selinux_exec_context",
                    "worker could not clear the pending PAM SELinux exec context"
                );
                drop(transaction);
                write_envelope(
                    writer,
                    WorkerResponse::SessionFailed {
                        code: WorkerSessionFailureCode::SessionChildFailed,
                    },
                )?;
                return Err(SessionError::AuthenticatedSessionFailed);
            }
            let child_terminal_fd = match terminal.lease().duplicate_terminal_fd() {
                Ok(fd) => fd,
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker failed to duplicate owned VT fd");
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
            let child_runner = match session_child_runner_factory
                .build_with_terminal(Path::new(&session_child_path), Some(child_terminal_fd))
            {
                Ok(runner) => runner,
                Err(error) => {
                    warn!(username = %canonical_username, session = %session.session.id, ?error, "worker failed to build session child runner");
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
            debug!(
                stage = "before_child_spawn",
                pam_selinux_exec_context_present = selinux_exec_context.is_some(),
                "prepared SELinux exec-context handoff for session child"
            );
            let runtime = match (
                SessionChildUnixPath::new(&credentials.identity.home),
                SessionChildUnixPath::new(&credentials.identity.shell),
                SessionChildUnixPath::new(&session_probe_path),
            ) {
                (Ok(home), Ok(shell), Ok(probe_path)) => SessionChildRuntimeContext {
                    home,
                    shell,
                    session_type: match session.session.kind {
                        niralis_protocol::SessionKind::Wayland => "wayland",
                        niralis_protocol::SessionKind::X11 => "x11",
                    }
                    .to_owned(),
                    session_class: "user".to_owned(),
                    session_desktop: session.session.id.clone(),
                    session_id: logind.id.as_str().to_owned(),
                    runtime_dir: SessionChildUnixPath {
                        bytes: pam_environment.runtime_dir.bytes,
                    },
                    seat: terminal.lease().seat().as_str().to_owned(),
                    vtnr: terminal.lease().vtnr().number(),
                    dbus_session_bus_address: None,
                    imported_locale: pam_environment.imported_locale,
                    selinux_exec_context: selinux_exec_context.clone(),
                    probe_path,
                    exec_plan: launch_plan,
                },
                _ => {
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
    include!("opened_handoff_scope.rs")
}
