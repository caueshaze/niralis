
#[test]
fn child_core_rejects_root_without_calling_dropper() {
    let dropper = StubDropper {
        result: Ok(AppliedCredentials {
            uid: 0,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        }),
        calls: AtomicUsize::new(0),
        target: Mutex::new(None),
    };
    let mut output = Vec::new();
    let code =
        super::run_child_process_with_dropper(Cursor::new(request(0)), &mut output, &dropper, 42);
    assert_ne!(code, 0);
    assert_eq!(dropper.calls.load(Ordering::SeqCst), 0);
    assert!(!output.is_empty());
}

#[test]
fn child_core_rejects_dropper_failure_and_mismatch() {
    for result in [
        Err(PrivilegeDropError::SetUidFailed),
        Ok(AppliedCredentials {
            uid: 999,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        }),
    ] {
        let dropper = StubDropper {
            result,
            calls: AtomicUsize::new(0),
            target: Mutex::new(None),
        };
        let mut output = Vec::new();
        let code = super::run_child_process_with_dropper(
            Cursor::new(request(1000)),
            &mut output,
            &dropper,
            42,
        );
        assert_ne!(code, 0);
        assert_eq!(dropper.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn maximum_supported_credentials_fit_the_child_protocol() {
    let start = u32::MAX - 65_535;
    let credentials = super::protocol::SessionChildUnixCredentials {
        uid: 1000,
        gid: 0,
        supplementary_gids: (start..=u32::MAX).collect(),
    };
    let envelope = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildRequest::ApplyCredentials {
            canonical_username: "canonical-user".to_owned(),
            session_id: "niri".to_owned(),
            credentials,
            runtime: runtime(),
            terminal: None,
        },
    };
    let payload = serde_json::to_vec(&envelope).expect("maximum request should serialize");
    assert!(payload.len() + 1 <= super::protocol::MAX_SESSION_CHILD_MESSAGE_BYTES);
}

#[test]
fn ready_binding_rejects_each_identity_or_credential_mismatch() {
    let expectation = super::SessionChildExpectation {
        canonical_username: "canonical-user".to_owned(),
        session_id: "niri".to_owned(),
        target_credentials: PrivilegeDropTarget {
            uid: 1000,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        },
        runtime: runtime(),
        terminal: None,
    };
    let expected = SessionChildUnixCredentials {
        uid: 1000,
        gid: 1000,
        supplementary_gids: vec![10, 20],
    };

    let cases = [
        ("username", "wrong-user".to_owned(), expected.clone()),
        ("session", "wrong-session".to_owned(), expected.clone()),
        (
            "pid",
            "canonical-user".to_owned(),
            SessionChildUnixCredentials {
                uid: expected.uid,
                gid: expected.gid,
                supplementary_gids: expected.supplementary_gids.clone(),
            },
        ),
        (
            "uid",
            "canonical-user".to_owned(),
            SessionChildUnixCredentials {
                uid: 999,
                ..expected.clone()
            },
        ),
        (
            "gid",
            "canonical-user".to_owned(),
            SessionChildUnixCredentials {
                gid: 999,
                ..expected.clone()
            },
        ),
        (
            "supplementary-gids",
            "canonical-user".to_owned(),
            SessionChildUnixCredentials {
                supplementary_gids: vec![10, 30],
                ..expected.clone()
            },
        ),
    ];

    for (field, username, applied_credentials) in cases {
        let session_id = if field == "session" {
            "wrong-session".to_owned()
        } else {
            "niri".to_owned()
        };
        let child_pid = if field == "pid" { 43 } else { 42 };
        let response = SessionChildResponse::Ready {
            canonical_username: username,
            session_id,
            child_pid,
            applied_credentials,
            credential_proof: super::protocol::SessionChildCredentialProof {
                real_uid: 1000,
                effective_uid: 1000,
                saved_uid: 1000,
                real_gid: 1000,
                effective_gid: 1000,
                saved_gid: 1000,
                supplementary_gids: vec![10, 20],
            },
            isolation_proof: proof(),
            process_identity: SessionProcessIdentityProof {
                pid: child_pid,
                sid: 42,
                pgid: 42,
            },
            runtime_environment: SessionRuntimeEnvironmentProof {
                home: runtime().home.clone(),
                user: "canonical-user".into(),
                logname: "canonical-user".into(),
                shell: runtime().shell.clone(),
                path: super::DEFAULT_SESSION_PATH.into(),
                session_type: "wayland".into(),
                session_class: "user".into(),
                session_desktop: "niri".into(),
                session_id: "niri".into(),
                runtime_dir: runtime().runtime_dir.clone(),
                seat: "seat0".into(),
                vtnr: 1,
                dbus_session_bus_address: None,
                imported_locale: Vec::new(),
                forbidden_variables_present: Vec::new(),
                user_bus_connected: true,
                cwd: runtime().home,
                exec_plan: runtime().exec_plan,
            },
            exec_probe_version: SESSION_EXEC_PROBE_VERSION,
            terminal_proof: None,
        };

        assert_eq!(
            super::validate_ready_response(response, &expectation, 42, false),
            Err(super::SessionChildError::ProtocolFailed),
            "mismatch in {field} must be rejected"
        );
    }
}
