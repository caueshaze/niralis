{
    if launch_plan.validate().is_err() {
        write_envelope(
            writer,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::LaunchSpecMalformed,
            },
        )?;
        return Err(SessionError::AuthenticatedSessionFailed);
    }
    let executable =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(launch_plan.executable.clone()));
    let executable_metadata = std::fs::metadata(&executable);
    let executable_ok = executable_metadata
        .as_ref()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if !executable_ok {
        write_envelope(
            writer,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::ExecutableUnavailable,
            },
        )?;
        return Err(SessionError::AuthenticatedSessionFailed);
    }
    let watchdog = match authorize_launch_watchdog(&request.session.id) {
        Ok(duration) => duration,
        Err(error) => {
            warn!(session = %request.session.id, ?error, "real graphical session rejected before PAM");
            write_rejection(writer, WorkerErrorCode::RealGraphicalSessionNotAuthorized)?;
            return Err(SessionError::WorkerRejected);
        }
    };
    // pam_systemd deliberately returns PAM_SUCCESS without creating a session
    // when the calling PID is already a member of one. A daemon started via
    // ssh -> sudo inherits that session cgroup, and env_clear() cannot change
    // it. Fail before acquiring a VT or beginning PAM so this is explicit.
    match logind_resolver.resolve_by_pid(std::process::id()) {
        Ok(Some(_)) => {
            warn!(
                stage = "pre_pam_logind_membership",
                worker_already_in_logind_session = true,
                "worker must be launched by the system manager, not from an inherited login session"
            );
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::WorkerAlreadyInLogindSession,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
        Ok(None) => debug!(
            stage = "pre_pam_logind_membership",
            worker_already_in_logind_session = false,
            "worker is not associated with an existing logind session"
        ),
        Err(error) => warn!(
            stage = "pre_pam_logind_membership",
            ?error,
            "could not determine worker logind membership; continuing so PAM/logind remains authoritative"
        ),
    }
    info!(
        source_path = ?launch_plan.source_path,
        executable = ?launch_plan.executable,
        argc = launch_plan.argv.len(),
        "canonical session execution plan accepted"
    );
    let control_listener = if control_path.as_os_str().is_empty() {
        None
    } else {
        Some(bind_control_listener(&control_path)?)
    };
    let seat = niralis_auth::SeatId::new("seat0".to_owned())
        .ok_or(SessionError::AuthenticatedSessionFailed)?;
    let mut terminal = match virtual_terminal_allocator.allocate(&seat) {
        Ok(terminal) => VirtualTerminalGuard::new(terminal),
        Err(error) => {
            warn!(username = %request.username, session = %request.session.id, ?error, "worker failed to allocate virtual terminal");
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::OpenFailed,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
    };
    let authenticator = factory.build(&pam_service);
    let auth_result = authenticator.authenticate(&request.username, password.expose());
    drop(password);
    let mut transaction = match auth_result {
        Ok(transaction) => transaction,
        Err(AuthError::LoginFailed) => {
            info!(username = %request.username, session = %request.session.id, "worker PAM authentication failed");
            write_envelope(writer, WorkerResponse::AuthenticationFailed)?;
            return Err(SessionError::AuthenticationFailed);
        }
        Err(AuthError::InfrastructureFailed) => {
            warn!(
                username = %request.username,
                session = %request.session.id,
                "worker PAM infrastructure failed before authentication completed"
            );
            write_rejection(writer, WorkerErrorCode::InternalError)?;
            return Err(SessionError::WorkerRejected);
        }
        Err(AuthError::AuthenticatedIdentityUnavailable) => {
            warn!(
                username = %request.username,
                session = %request.session.id,
                "worker could not determine PAM authenticated identity"
            );
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::PamIdentityUnavailable,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
    };
    let pam_username = transaction.user().username.clone();
    let identity = match identity_resolver.resolve(&pam_username) {
        Ok(identity) => identity,
        Err(error) => {
            warn!(
                username = %pam_username,
                session = %request.session.id,
                ?error,
                "worker failed to resolve canonical Unix identity"
            );
            drop(transaction);
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::IdentityResolutionFailed,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
    };
    let supplementary_gids = match supplementary_groups_resolver.resolve(&identity) {
        Ok(groups) => groups,
        Err(error) => {
            warn!(
                username = %identity.username,
                session = %request.session.id,
                ?error,
                "worker failed to resolve supplementary Unix groups"
            );
            drop(transaction);
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::SupplementaryGroupsResolutionFailed,
                },
            )?;
            return Err(SessionError::AuthenticatedSessionFailed);
        }
    };
    let credentials = ResolvedUnixCredentials {
        identity,
        supplementary_gids,
    };
    debug!(
        username = %credentials.identity.username,
        uid = credentials.identity.uid,
        gid = credentials.identity.gid,
        supplementary_group_count = credentials.supplementary_gids.len(),
        "resolved canonical Unix credentials"
    );
    let canonical_username = credentials.identity.username.clone();

    let expected_type = match request.session.kind {
        niralis_protocol::SessionKind::Wayland => "wayland",
        niralis_protocol::SessionKind::X11 => "x11",
    };
    let metadata = niralis_auth::PamSessionMetadata {
        session_type: match request.session.kind {
            niralis_protocol::SessionKind::Wayland => niralis_auth::PamSessionType::Wayland,
            niralis_protocol::SessionKind::X11 => niralis_auth::PamSessionType::X11,
        },
        session_class: niralis_auth::PamSessionClass::User,
        session_desktop: request.session.id.clone(),
        seat: Some(terminal.lease().seat().clone()),
        vtnr: Some(terminal.lease().vtnr()),
        tty: Some(format!("/dev/tty{}", terminal.lease().vtnr().number())),
    };
    let open_result = catch_unwind(AssertUnwindSafe(|| transaction.open_session(&metadata)));
    let session = StartedSession {
        username: request.username,
        session: request.session,
    };

    match open_result {
        Ok(Ok(())) => include!("opened_environment.rs"),
        Ok(Err(_)) => {
            warn!(username = %canonical_username, session = %session.session.id, "worker PAM session open failed");
            drop(transaction);
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::OpenFailed,
                },
            )?;
            Err(SessionError::AuthenticatedSessionFailed)
        }
        Err(_) => {
            warn!(username = %canonical_username, session = %session.session.id, "worker PAM session open panicked");
            drop(transaction);
            write_envelope(
                writer,
                WorkerResponse::SessionFailed {
                    code: WorkerSessionFailureCode::InternalPanic,
                },
            )?;
            Err(SessionError::AuthenticatedSessionFailed)
        }
    }
}
