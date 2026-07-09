use std::io::Cursor;
use std::sync::atomic::Ordering;

use niralis_session::{WorkerEnvelope, WorkerResponse};

use crate::runtime::{run_worker_process_with_dependencies, WorkerDependencies};

use super::support::{identity, request, StubFactory, StubIdentityResolver, TrackingState};

#[test]
fn pam_worker_returns_ready_after_short_lifecycle() {
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
                authenticate_ok: true,
                open_ok: true,
                open_panics: false,
                pam_username: "caue",
            },
            identity_resolver: &StubIdentityResolver {
                state: state.clone(),
                result: Ok(identity()),
            },
        },
    )
    .expect("worker should succeed");

    let response: WorkerEnvelope<WorkerResponse> =
        serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should parse");
    assert_eq!(state.authenticate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.resolve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.open_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
    assert!(matches!(response.message, WorkerResponse::Ready { .. }));
}
