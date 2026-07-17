fn fixture_report(expectation: SessionChildExpectation, pid: u32) -> SessionChildReport {
    let credentials = &expectation.target_credentials;
    SessionChildReport {
        canonical_username: expectation.canonical_username.clone(),
        session_id: expectation.session_id,
        child_pid: pid,
        applied_credentials: AppliedCredentials {
            uid: credentials.uid,
            gid: credentials.gid,
            supplementary_gids: credentials.supplementary_gids.clone(),
        },
        credential_proof: crate::session_child::SessionChildCredentialProof {
            real_uid: credentials.uid,
            effective_uid: credentials.uid,
            saved_uid: credentials.uid,
            real_gid: credentials.gid,
            effective_gid: credentials.gid,
            saved_gid: credentials.gid,
            supplementary_gids: credentials.supplementary_gids.clone(),
        },
        isolation_proof: PostDropIsolationProof {
            capabilities: CapabilityState {
                effective: vec![],
                permitted: vec![],
                inheritable: vec![],
                ambient: vec![],
                bounding: vec![],
                cap_last_cap: 0,
            },
            securebits: 0,
            no_new_privs: false,
            open_fds: vec![0, 1, 2],
        },
        process_identity: crate::session_child::ProcessIdentityProof {
            pid,
            sid: pid,
            pgid: pid,
        },
        runtime_environment: crate::session_child::RuntimeEnvironmentProof {
            home: expectation.runtime.home.clone(),
            user: expectation.canonical_username.clone(),
            logname: expectation.canonical_username,
            shell: expectation.runtime.shell.clone(),
            path: crate::session_child::DEFAULT_SESSION_PATH.into(),
            session_type: expectation.runtime.session_type,
            session_class: expectation.runtime.session_class,
            session_desktop: expectation.runtime.session_desktop,
            session_id: expectation.runtime.session_id,
            runtime_dir: expectation.runtime.runtime_dir,
            seat: expectation.runtime.seat,
            vtnr: expectation.runtime.vtnr,
            dbus_session_bus_address: None,
            imported_locale: Vec::new(),
            forbidden_variables_present: Vec::new(),
            user_bus_connected: true,
            cwd: expectation.runtime.home,
            exec_plan: expectation.runtime.exec_plan,
        },
        exec_probe_version: crate::session_child::SESSION_EXEC_PROBE_VERSION,
        terminal_proof: expectation.terminal.map(|terminal| {
            crate::session_child::SessionChildTerminalProof {
                seat: terminal.seat,
                vtnr: terminal.vtnr,
                fd: terminal.fd,
                device_major: 4,
                device_minor: terminal.vtnr,
                controlling_sid: pid,
                foreground_pgid: pid,
            }
        }),
    }
}
