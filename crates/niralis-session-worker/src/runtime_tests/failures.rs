use std::io::Cursor;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use niralis_auth::AuthError;
use niralis_session::{WorkerEnvelope, WorkerResponse, WorkerSessionFailureCode};

use crate::identity::IdentityError;
use crate::runtime::{
    run_worker_process_with_dependencies, StubRuntimeDirValidator, WorkerDependencies,
};

use super::support::{
    identity, request, StubChildFactory, StubFactory, StubGroupsResolver, StubIdentityResolver,
    StubLogind, StubVtAllocator, TrackingState,
};

#[test]
fn pam_worker_distinguishes_auth_identity_and_session_failures() {
    for (
        auth_ok,
        identity_result,
        open_ok,
        open_panics,
        expected,
        resolve_calls,
        open_calls,
        drops,
        groups_result,
        groups_calls,
    ) in [
        (
            Err(AuthError::LoginFailed),
            Ok(identity()),
            false,
            false,
            WorkerResponse::AuthenticationFailed,
            0,
            0,
            0,
            Ok(vec![]),
            0,
        ),
        (
            Err(AuthError::InfrastructureFailed),
            Ok(identity()),
            false,
            false,
            WorkerResponse::Rejected {
                code: niralis_session::WorkerErrorCode::InternalError,
            },
            0,
            0,
            0,
            Ok(vec![]),
            0,
        ),
        (
            Err(AuthError::AuthenticatedIdentityUnavailable),
            Ok(identity()),
            false,
            false,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::PamIdentityUnavailable,
            },
            0,
            0,
            0,
            Ok(vec![]),
            0,
        ),
        (
            Ok(()),
            Err(IdentityError::LookupFailed),
            false,
            false,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::IdentityResolutionFailed,
            },
            1,
            0,
            1,
            Ok(vec![]),
            0,
        ),
        (
            Ok(()),
            Ok(identity()),
            false,
            false,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::SupplementaryGroupsResolutionFailed,
            },
            1,
            0,
            1,
            Err(crate::identity::GroupResolutionError::LookupFailed),
            1,
        ),
        (
            Ok(()),
            Ok(identity()),
            false,
            false,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::OpenFailed,
            },
            1,
            1,
            1,
            Ok(vec![]),
            1,
        ),
        (
            Ok(()),
            Ok(identity()),
            false,
            true,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::InternalPanic,
            },
            1,
            1,
            1,
            Ok(vec![]),
            1,
        ),
    ] {
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
                    auth_result: auth_ok.clone(),
                    open_ok,
                    open_panics,
                    pam_username: "caue",
                },
                identity_resolver: &StubIdentityResolver {
                    state: state.clone(),
                    result: identity_result.clone(),
                    last_username: Arc::new(Mutex::new(None)),
                },
                supplementary_groups_resolver: &StubGroupsResolver {
                    state: state.clone(),
                    result: groups_result.clone(),
                    last_username: Arc::new(Mutex::new(None)),
                },
                session_child_runner_factory: &StubChildFactory {
                    state: state.clone(),
                    result: groups_result
                        .as_ref()
                        .map(|_| ())
                        .map_err(|_| crate::session_child::SessionChildError::ProtocolFailed),
                },
                logind_resolver: &StubLogind::default(),
                virtual_terminal_allocator: &StubVtAllocator,
                runtime_dir_validator: &StubRuntimeDirValidator,
            },
        );

        assert!(result.is_err());
        let response: WorkerEnvelope<WorkerResponse> =
            serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should parse");
        assert_eq!(response.message, expected);
        assert_eq!(state.authenticate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.resolve_calls.load(Ordering::SeqCst), resolve_calls);
        assert_eq!(state.groups_calls.load(Ordering::SeqCst), groups_calls);
        assert_eq!(state.open_calls.load(Ordering::SeqCst), open_calls);
        assert_eq!(state.drops.load(Ordering::SeqCst), drops);
        assert_eq!(
            state.child_calls.load(Ordering::SeqCst),
            if open_ok { 1 } else { 0 }
        );
    }
}

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
