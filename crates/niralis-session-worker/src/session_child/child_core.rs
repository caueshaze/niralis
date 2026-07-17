
pub(crate) fn run_child_process_with_dependencies(
    mut reader: impl Read,
    mut writer: impl Write,
    dropper: &impl PrivilegeDropper,
    fd_sanitizer: &impl InheritedFdSanitizer,
    auditor: &impl PostDropAuditor,
    child_pid: u32,
) -> i32 {
    let bytes = match read_child_response(&mut reader) {
        Ok(bytes) => bytes,
        Err(_) => return 1,
    };
    let request: SessionChildEnvelope<SessionChildRequest> = match parse_request(&bytes) {
        Ok(request) => request,
        Err(code) => {
            let _ = write_rejection(&mut writer, code);
            return 1;
        }
    };
    if request.version != SESSION_CHILD_PROTOCOL_VERSION {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::UnsupportedVersion);
        return 1;
    }
    let SessionChildRequest::ApplyCredentials {
        canonical_username,
        session_id,
        credentials,
        runtime,
        terminal,
    } = request.message;
    if credentials.uid == 0 {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::RootUidDisallowed);
        return 1;
    }
    let mut allowed_inherited_fds = terminal
        .as_ref()
        .map_or_else(Vec::new, |value| vec![value.fd]);
    // FD 4 is the parent's CLOEXEC status pipe.  It is needed until the
    // commit/exec handoff completes, then is closed automatically by execve.
    if child_pid == std::process::id() {
        allowed_inherited_fds.push(4);
    }
    if fd_sanitizer
        .sanitize_with_allowlist(&allowed_inherited_fds)
        .is_err()
    {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::FdSanitizationFailed);
        return 1;
    }
    let target = PrivilegeDropTarget::from(credentials);
    let applied = match dropper.drop_privileges(&target) {
        Ok(applied) => applied,
        Err(PrivilegeDropError::RootUidDisallowed) => {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::RootUidDisallowed);
            return 1;
        }
        Err(error) => {
            eprintln!("session child privilege drop failed error={error}");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::PrivilegeDropFailed);
            return 1;
        }
    };
    let applied_credentials = SessionChildUnixCredentials::from(&applied);
    if applied_credentials != SessionChildUnixCredentials::from(&target) {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::CredentialMismatch);
        return 1;
    }
    if child_pid == std::process::id() && clear_post_drop_capabilities().is_err() {
        eprintln!("session child post-drop capability sanitization failed");
        let _ = write_rejection(&mut writer, SessionChildErrorCode::IsolationAuditFailed);
        return 1;
    }
    let proof = match auditor.audit() {
        Ok(proof) => proof,
        Err(_) => {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::IsolationAuditFailed);
            return 1;
        }
    };
    if let Err(error) = validate_isolation_proof_with_allowed_fds(&proof, &allowed_inherited_fds) {
        eprintln!(
            "session child isolation policy failed error={error} effective_capability_count={} permitted_capability_count={} inheritable_capability_count={} inheritable_capabilities={:?} ambient_capability_count={} bounding_capability_count={} securebits={} no_new_privs={} open_fds={:?} allowed_inherited_fds={allowed_inherited_fds:?}",
            proof.capabilities.effective.len(),
            proof.capabilities.permitted.len(),
            proof.capabilities.inheritable.len(),
            proof.capabilities.inheritable,
            proof.capabilities.ambient.len(),
            proof.capabilities.bounding.len(),
            proof.securebits,
            proof.no_new_privs,
            proof.open_fds,
        );
        let _ = write_rejection(&mut writer, SessionChildErrorCode::IsolationPolicyFailed);
        return 1;
    }
    // The production child replaces itself with the trusted probe. Test seams use
    // synthetic PIDs and retain the response path for deterministic unit tests.
    let terminal_proof = if child_pid == std::process::id() {
        if unsafe { libc::setsid() } < 0 {
            eprintln!("session child terminal setup failed stage=setsid");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::SessionBoundaryFailed);
            return 1;
        }
        let terminal = match terminal.as_ref() {
            Some(terminal) if terminal.fd == 3 => terminal,
            _ => {
                eprintln!("session child terminal setup failed stage=terminal_fd");
                let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
                return 1;
            }
        };
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(terminal.fd, &mut stat) } < 0
            || libc::major(stat.st_rdev) as u32 != terminal.device_major
            || libc::minor(stat.st_rdev) as u32 != terminal.device_minor
        {
            eprintln!("session child terminal setup failed stage=fstat");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        if unsafe { libc::ioctl(terminal.fd, libc::TIOCSCTTY, 0) } < 0 {
            eprintln!("session child terminal setup failed stage=tiocsctty");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        let previous_sigttou = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
        let foreground = unsafe { libc::tcsetpgrp(terminal.fd, libc::getpgrp()) };
        unsafe { libc::signal(libc::SIGTTOU, previous_sigttou) };
        if foreground != 0 {
            eprintln!("session child terminal setup failed stage=tcsetpgrp");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        let sid = unsafe { libc::tcgetsid(terminal.fd) };
        let pgid = unsafe { libc::tcgetpgrp(terminal.fd) };
        let pid = unsafe { libc::getpid() };
        if sid <= 0 || pgid <= 0 || sid as u32 != pid as u32 || pgid as u32 != pid as u32 {
            eprintln!("session child terminal setup failed stage=terminal_identity");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        Some(SessionChildTerminalProof {
            seat: terminal.seat.clone(),
            vtnr: terminal.vtnr,
            fd: terminal.fd,
            device_major: terminal.device_major,
            device_minor: terminal.device_minor,
            controlling_sid: sid as u32,
            foreground_pgid: pgid as u32,
        })
    } else {
        None
    };
    if child_pid == std::process::id() {
        if crate::termination::restore_payload_signal_state().is_err() {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::IsolationAuditFailed);
            return 1;
        }
        let home = match runtime.home.to_path_buf() {
            Ok(path) if path.is_absolute() => path,
            _ => {
                let _ =
                    write_rejection(&mut writer, SessionChildErrorCode::HomeDirectoryUnavailable);
                return 1;
            }
        };
        if std::env::set_current_dir(&home).is_err() {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::HomeDirectoryUnavailable);
            return 1;
        }
        if install_runtime_environment(&runtime, &canonical_username).is_err() {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::InvalidRuntimeContext);
            return 1;
        }
        if crate::prove_user_bus().is_err() {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::RuntimeProbeFailed);
            return 1;
        }
    }
    // The real child must not claim readiness before the post-exec probe has
    // re-audited the process. Unit-only callers pass a synthetic PID and keep
    // the response construction below as a narrow seam for child-core tests.
    if child_pid == std::process::id() {
        if exec_probe(
            &runtime,
            &canonical_username,
            &session_id,
            terminal.as_ref(),
        )
        .is_err()
        {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::ExecFailed);
        }
        return 1;
    }

    write_ready_response(
        &mut writer,
        canonical_username,
        session_id,
        child_pid,
        applied_credentials,
        &proof,
        runtime,
        terminal_proof,
    )
}
