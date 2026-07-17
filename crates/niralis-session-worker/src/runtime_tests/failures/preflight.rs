
#[test]
fn pam_worker_rejects_an_inherited_logind_session_before_pam_or_vt() {
    struct ExistingSessionLogind;

    impl crate::LogindSessionResolver for ExistingSessionLogind {
        fn resolve_by_pid(
            &self,
            _pid: u32,
        ) -> Result<Option<crate::LogindSessionIdentity>, crate::LogindError> {
            Ok(Some(crate::LogindSessionIdentity {
                id: crate::LogindSessionId::new("ssh-session".to_owned()).unwrap(),
                uid: 1000,
                session_type: "tty".to_owned(),
                class: "user".to_owned(),
                desktop: None,
                seat: None,
                vtnr: None,
            }))
        }

        fn resolve_by_id(
            &self,
            _id: &crate::LogindSessionId,
        ) -> Result<Option<crate::LogindSessionIdentity>, crate::LogindError> {
            unreachable!("pre-PAM rejection must not query a session by id")
        }
    }

    let mut reader = Cursor::new(format!(
        "{}\n",
        serde_json::to_string(&request()).expect("json")
    ));
    let mut writer = Vec::new();
    let state = TrackingState::default();

    let result = run_worker_process_with_dependencies(
        &mut reader,
        &mut writer,
        WorkerDependencies {
            authenticator_factory: &StubFactory {
                state: state.clone(),
                auth_result: Ok(()),
                open_ok: true,
                open_panics: false,
                pam_username: "caue",
            },
            identity_resolver: &StubIdentityResolver {
                state: state.clone(),
                result: Ok(identity()),
                last_username: Arc::new(Mutex::new(None)),
            },
            supplementary_groups_resolver: &StubGroupsResolver {
                state: state.clone(),
                result: Ok(vec![]),
                last_username: Arc::new(Mutex::new(None)),
            },
            session_child_runner_factory: &StubChildFactory {
                state: state.clone(),
                result: Ok(()),
            },
            logind_resolver: &ExistingSessionLogind,
            virtual_terminal_allocator: &StubVtAllocator,
            runtime_dir_validator: &StubRuntimeDirValidator,
            selinux_context_manager: &StubSelinux::default(),
            payload_scope_manager: &StubPayloadScopeManager,
            launch_phase_gate: &crate::runtime::NoopLaunchPhaseGate,
        },
    );

    assert!(result.is_err());
    let response: WorkerEnvelope<WorkerResponse> =
        serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should parse");
    assert_eq!(
        response.message,
        WorkerResponse::SessionFailed {
            code: WorkerSessionFailureCode::WorkerAlreadyInLogindSession,
        }
    );
    assert_eq!(state.authenticate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.open_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.child_calls.load(Ordering::SeqCst), 0);
}
