
fn write_ready_response(
    writer: &mut impl Write,
    canonical_username: String,
    session_id: String,
    child_pid: u32,
    applied_credentials: SessionChildUnixCredentials,
    runtime_proof: &PostDropIsolationProof,
    runtime: SessionChildRuntimeContext,
    terminal_proof: Option<SessionChildTerminalProof>,
) -> i32 {
    let response = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildResponse::Ready {
            canonical_username: canonical_username.clone(),
            session_id,
            child_pid,
            applied_credentials: applied_credentials.clone(),
            credential_proof: SessionChildCredentialProof {
                real_uid: applied_credentials.uid,
                effective_uid: applied_credentials.uid,
                saved_uid: applied_credentials.uid,
                real_gid: applied_credentials.gid,
                effective_gid: applied_credentials.gid,
                saved_gid: applied_credentials.gid,
                supplementary_gids: applied_credentials.supplementary_gids.clone(),
            },
            isolation_proof: SessionChildIsolationProof::from(runtime_proof),
            process_identity: SessionProcessIdentityProof {
                pid: child_pid,
                sid: child_pid,
                pgid: child_pid,
            },
            runtime_environment: SessionRuntimeEnvironmentProof {
                home: runtime.home.clone(),
                user: canonical_username.clone(),
                logname: canonical_username.clone(),
                shell: runtime.shell.clone(),
                path: DEFAULT_SESSION_PATH.to_owned(),
                session_type: runtime.session_type.clone(),
                session_class: runtime.session_class.clone(),
                session_desktop: runtime.session_desktop.clone(),
                session_id: runtime.session_id.clone(),
                runtime_dir: runtime.runtime_dir.clone(),
                seat: runtime.seat.clone(),
                vtnr: runtime.vtnr,
                dbus_session_bus_address: runtime.dbus_session_bus_address.clone(),
                imported_locale: runtime.imported_locale.clone(),
                forbidden_variables_present: Vec::new(),
                user_bus_connected: true,
                cwd: runtime.home,
                exec_plan: runtime.exec_plan.clone(),
            },
            exec_probe_version: SESSION_EXEC_PROBE_VERSION,
            terminal_proof,
        },
    };
    if let Err(error) = serde_json::to_writer(&mut *writer, &response) {
        eprintln!("session child ready response failed stage=serialize error={error}");
        return 1;
    }
    if let Err(error) = writer.write_all(b"\n") {
        eprintln!(
            "session child ready response failed stage=write errno={:?} error={error}",
            error.raw_os_error()
        );
        return 1;
    }
    if let Err(error) = writer.flush() {
        eprintln!(
            "session child ready response failed stage=flush errno={:?} error={error}",
            error.raw_os_error()
        );
        return 1;
    }
    0
}

fn install_runtime_environment(
    runtime: &SessionChildRuntimeContext,
    username: &str,
) -> Result<(), ()> {
    unsafe {
        libc::clearenv();
    }
    let mut entries = vec![
        (
            "HOME".to_owned(),
            runtime.home.to_path_buf().map_err(|_| ())?,
        ),
        ("USER".to_owned(), std::path::PathBuf::from(username)),
        ("LOGNAME".to_owned(), std::path::PathBuf::from(username)),
        (
            "SHELL".to_owned(),
            runtime.shell.to_path_buf().map_err(|_| ())?,
        ),
        (
            "PATH".to_owned(),
            std::path::PathBuf::from(DEFAULT_SESSION_PATH),
        ),
        (
            "XDG_SESSION_TYPE".to_owned(),
            std::path::PathBuf::from(&runtime.session_type),
        ),
        (
            "XDG_SESSION_CLASS".to_owned(),
            std::path::PathBuf::from(&runtime.session_class),
        ),
        (
            "XDG_SESSION_DESKTOP".to_owned(),
            std::path::PathBuf::from(&runtime.session_desktop),
        ),
        (
            "XDG_SESSION_ID".to_owned(),
            std::path::PathBuf::from(&runtime.session_id),
        ),
        (
            "XDG_RUNTIME_DIR".to_owned(),
            runtime.runtime_dir.to_path_buf().map_err(|_| ())?,
        ),
        (
            "XDG_SEAT".to_owned(),
            std::path::PathBuf::from(&runtime.seat),
        ),
        (
            "XDG_VTNR".to_owned(),
            std::path::PathBuf::from(runtime.vtnr.to_string()),
        ),
    ];
    if let Some(address) = &runtime.dbus_session_bus_address {
        entries.push((
            "DBUS_SESSION_BUS_ADDRESS".to_owned(),
            std::path::PathBuf::from(address),
        ));
    }
    for (key, value) in &runtime.imported_locale {
        entries.push((key.clone(), std::path::PathBuf::from(value)));
    }
    use std::os::unix::ffi::OsStrExt;
    for (key, value) in entries {
        let key = std::ffi::CString::new(key).map_err(|_| ())?;
        let value = std::ffi::CString::new(value.as_os_str().as_bytes()).map_err(|_| ())?;
        if unsafe { libc::setenv(key.as_ptr(), value.as_ptr(), 1) } != 0 {
            return Err(());
        }
    }
    Ok(())
}

const PROBE_HANDOFF_FD: libc::c_int = 5;

fn exec_probe(
    runtime: &SessionChildRuntimeContext,
    username: &str,
    session_id: &str,
    terminal: Option<&SessionChildTerminalContext>,
) -> Result<(), ()> {
    let probe = runtime.probe_path.to_path_buf().map_err(|_| ())?;
    if !probe.is_absolute() {
        return Err(());
    }
    let handoff = SessionProbeHandoff {
        exec_plan: runtime.exec_plan.clone(),
        selinux_exec_context: runtime.selinux_exec_context.clone(),
    };
    let payload = serde_json::to_vec(&handoff).map_err(|_| ())?;
    if payload.is_empty() || payload.len() > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
        return Err(());
    }
    let name = std::ffi::CString::new("niralis-probe-handoff").map_err(|_| ())?;
    let handoff_fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC) };
    if handoff_fd < 0 {
        return Err(());
    }
    let result = (|| {
        let mut file = unsafe { std::fs::File::from_raw_fd(handoff_fd) };
        file.write_all(&payload).map_err(|_| ())?;
        file.sync_all().map_err(|_| ())?;
        if file.rewind().is_err() {
            return Err(());
        }
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(());
        }
        let source = file.into_raw_fd();
        if unsafe { libc::dup2(source, PROBE_HANDOFF_FD) } < 0 {
            unsafe { libc::close(source) };
            return Err(());
        }
        if source != PROBE_HANDOFF_FD {
            unsafe { libc::close(source) };
        }
        if unsafe { libc::fcntl(PROBE_HANDOFF_FD, libc::F_SETFD, 0) } < 0 {
            return Err(());
        }
        Ok(())
    })();
    result?;

    let mut command = Command::new(probe);
    command.arg(username).arg(session_id);
    if let Some(terminal) = terminal {
        command
            .arg("--terminal-seat")
            .arg(&terminal.seat)
            .arg("--terminal-vtnr")
            .arg(terminal.vtnr.to_string())
            .arg("--terminal-major")
            .arg(terminal.device_major.to_string())
            .arg("--terminal-minor")
            .arg(terminal.device_minor.to_string());
    }
    let _ = std::os::unix::process::CommandExt::exec(&mut command);
    Err(())
}
