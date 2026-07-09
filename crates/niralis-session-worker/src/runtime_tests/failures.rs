use std::io::Cursor;
use std::sync::atomic::Ordering;

use niralis_session::{WorkerEnvelope, WorkerResponse, WorkerSessionFailureCode};

use crate::identity::IdentityError;
use crate::runtime::{run_worker_process_with_dependencies, WorkerDependencies};

use super::support::{identity, request, StubFactory, StubIdentityResolver, TrackingState};

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
    ) in [
        (
            false,
            Ok(identity()),
            false,
            false,
            WorkerResponse::AuthenticationFailed,
            0,
            0,
            0,
        ),
        (
            true,
            Err(IdentityError::LookupFailed),
            false,
            false,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::IdentityResolutionFailed,
            },
            1,
            0,
            1,
        ),
        (
            true,
            Ok(identity()),
            false,
            false,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::OpenFailed,
            },
            1,
            1,
            1,
        ),
        (
            true,
            Ok(identity()),
            false,
            true,
            WorkerResponse::SessionFailed {
                code: WorkerSessionFailureCode::InternalPanic,
            },
            1,
            1,
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
                    authenticate_ok: auth_ok,
                    open_ok,
                    open_panics,
                    pam_username: "caue",
                },
                identity_resolver: &StubIdentityResolver {
                    state: state.clone(),
                    result: identity_result.clone(),
                },
            },
        );

        assert!(result.is_err());
        let response: WorkerEnvelope<WorkerResponse> =
            serde_json::from_slice(&writer[..writer.len() - 1]).expect("response should parse");
        assert_eq!(response.message, expected);
        assert_eq!(state.authenticate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.resolve_calls.load(Ordering::SeqCst), resolve_calls);
        assert_eq!(state.open_calls.load(Ordering::SeqCst), open_calls);
        assert_eq!(state.drops.load(Ordering::SeqCst), drops);
    }
}
