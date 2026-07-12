use std::io::Cursor;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::session_child::SessionChildError;
use niralis_session::{WorkerEnvelope, WorkerResponse};

use crate::runtime::{
    run_worker_process_with_dependencies, StubRuntimeDirValidator, WorkerDependencies,
};

use super::support::{
    identity, request, StubChildFactory, StubFactory, StubGroupsResolver, StubIdentityResolver,
    StubLogind, StubVtAllocator, TrackingState,
};

#[test]
fn pam_worker_reports_started_before_lifecycle_completion() {
    let mut reader = Cursor::new(format!(
        "{}\n",
        serde_json::to_string(&request()).expect("json")
    ));
    let mut writer = Vec::new();
    let state = TrackingState::default();

    run_worker_process_with_dependencies(
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
                result: Ok(vec![1001, 1002]),
                last_username: Arc::new(Mutex::new(None)),
            },
            session_child_runner_factory: &StubChildFactory {
                state: state.clone(),
                result: Ok(()),
            },
            logind_resolver: &StubLogind::default(),
            virtual_terminal_allocator: &StubVtAllocator,
            runtime_dir_validator: &StubRuntimeDirValidator,
        },
    )
    .expect("worker should succeed");

    let response: WorkerEnvelope<WorkerResponse> =
        serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should parse");
    assert_eq!(state.authenticate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.resolve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.groups_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.open_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
    assert_eq!(state.child_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.child_drop_observations.load(Ordering::SeqCst), 0);
    assert!(matches!(response.message, WorkerResponse::Started { .. }));
}

#[test]
fn identity_resolution_uses_pam_user_not_requested_username() {
    let mut reader = Cursor::new(format!(
        "{}\n",
        serde_json::to_string(&request()).expect("json")
    ));
    let mut writer = Vec::new();
    let state = TrackingState::default();
    let last_username = Arc::new(Mutex::new(None));
    let last_group_username = Arc::new(Mutex::new(None));
    let mut canonical_identity = identity();
    canonical_identity.username = "canonical-user".to_owned();

    run_worker_process_with_dependencies(
        &mut reader,
        &mut writer,
        WorkerDependencies {
            authenticator_factory: &StubFactory {
                state: state.clone(),
                auth_result: Ok(()),
                open_ok: true,
                open_panics: false,
                pam_username: "pam-user",
            },
            identity_resolver: &StubIdentityResolver {
                state: state.clone(),
                result: Ok(canonical_identity),
                last_username: last_username.clone(),
            },
            supplementary_groups_resolver: &StubGroupsResolver {
                state: state.clone(),
                result: Ok(vec![]),
                last_username: last_group_username.clone(),
            },
            session_child_runner_factory: &StubChildFactory {
                state: state.clone(),
                result: Ok(()),
            },
            logind_resolver: &StubLogind::default(),
            virtual_terminal_allocator: &StubVtAllocator,
            runtime_dir_validator: &StubRuntimeDirValidator,
        },
    )
    .expect("worker should succeed");

    assert_eq!(
        last_username
            .lock()
            .expect("last_username mutex should lock")
            .as_deref(),
        Some("pam-user")
    );
    assert_eq!(
        last_group_username
            .lock()
            .expect("last_group_username mutex should lock")
            .as_deref(),
        Some("canonical-user")
    );
}

#[test]
fn child_failure_drops_pam_transaction_after_child_returns() {
    let mut reader = Cursor::new(format!(
        "{}\n",
        serde_json::to_string(&request()).expect("json")
    ));
    let mut writer = Vec::new();
    let state = TrackingState::default();

    let result = crate::runtime::run_worker_process_with_dependencies(
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
                result: Err(SessionChildError::ProtocolFailed),
            },
            logind_resolver: &StubLogind::default(),
            virtual_terminal_allocator: &StubVtAllocator,
            runtime_dir_validator: &StubRuntimeDirValidator,
        },
    );

    assert!(result.is_err());
    assert_eq!(state.open_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.child_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.child_drop_observations.load(Ordering::SeqCst), 0);
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
    let response: WorkerEnvelope<WorkerResponse> =
        serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should parse");
    assert!(matches!(
        response.message,
        WorkerResponse::SessionFailed { .. }
    ));
}
