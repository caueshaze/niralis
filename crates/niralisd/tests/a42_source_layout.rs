use std::fs;
use std::path::PathBuf;

fn source(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = root
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root");
    fs::read_to_string(workspace.join(path)).expect("source file should exist")
}

#[test]
fn connection_authority_is_non_clonable() {
    let text = source("crates/niralisd/src/connection.rs");
    assert!(text.contains("pub struct GreeterConnectionAuthority"));
    let authority = text
        .split("pub struct GreeterConnectionAuthority")
        .nth(1)
        .unwrap();
    assert!(!authority.contains("Clone, Copy"));
}

#[test]
fn connection_authority_cannot_be_reconstructed_from_wire() {
    let text = source("crates/niralisd/src/connection.rs");
    assert!(text.contains("pub(crate) fn issue"));
    assert!(!text.contains("pub fn issue"));
}

#[test]
fn handler_never_decides_seat_availability() {
    let text = source("crates/niralisd/src/handler/mod.rs");
    assert!(!text.contains("SeatLifecycle::Free"));
    assert!(!text.contains("SeatLifecycle::Busy"));
}

#[test]
fn no_greeter_path_mutates_seat_directly() {
    let text = source("crates/niralisd/src/handler/mod.rs");
    assert!(!text.contains("admission.cancel"));
    assert!(!text.contains("admission.release"));
}

#[test]
fn socket_peer_validation_precedes_dispatch() {
    let text = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(text.find("peer_credentials").unwrap() < text.find("handle_authenticated").unwrap());
}

#[test]
fn unvalidated_peer_cannot_request_login() {
    let text = source("crates/niralisd/src/server/socket_nss.rs");
    let text = format!(
        "{}\n{}",
        text,
        source("crates/niralisd/src/server/client_protocol.rs")
    );
    assert!(text.contains("PeerCredentialsRejected"));
}

#[test]
fn wrong_peer_credentials_are_rejected_before_admission() {
    let text = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(text.contains("peer.uid != expected_peer.uid"));
    assert!(text.contains("peer.gid != expected_peer.gid"));
}

#[test]
fn oversized_frame_is_rejected_before_decode() {
    let text = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(
        text.find("let frame = match read_frame").unwrap() < text.find("let envelope").unwrap()
    );
}

#[test]
fn truncated_frame_is_rejected() {
    let text = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(text.contains("FrameTruncated"));
}

#[test]
fn stale_connection_epoch_is_rejected() {
    let text = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(text.contains("authority.matches"));
    assert!(text.contains("ConnectionAuthorityRejected"));
}

#[test]
fn wrong_seat_is_rejected() {
    let text = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(text.contains("&envelope.seat"));
}

#[test]
fn duplicate_sequence_is_rejected() {
    let text = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(text.contains("sequence.accept"));
}

#[test]
fn duplicate_request_id_is_rejected() {
    let text = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(text.contains("request_ids.insert"));
}

#[test]
fn regressive_sequence_is_rejected() {
    let text = source("crates/niralis-protocol/src/greeter.rs");
    assert!(text.contains("sequence <= self.last"));
}

#[test]
fn unknown_message_type_is_fail_closed() {
    let text = source("crates/niralis-protocol/src/greeter.rs");
    assert!(text.contains("UnknownMessageType"));
}

#[test]
fn response_does_not_expose_internal_identity() {
    let text = source("crates/niralis-protocol/src/greeter.rs");
    let response = text
        .split("pub struct GreeterResponseEnvelope")
        .nth(1)
        .unwrap();
    assert!(response.contains("request_id"));
    assert!(!response.contains("peer_identity"));
}

#[test]
fn disconnect_cancels_only_exact_precommit_transaction() {
    let text = source("crates/niralisd/src/handler/transactions.rs");
    assert!(text.contains("TransactionState::PreCommit"));
    assert!(text.contains("request_id: target_request_id"));
}

#[test]
fn disconnect_after_commit_does_not_release_seat() {
    let text = source("crates/niralisd/src/handler/transactions.rs");
    assert!(text.contains("TransactionState::Committed"));
}

#[test]
fn reconnect_cannot_control_old_transaction() {
    let text = source("crates/niralisd/src/handler/transactions.rs");
    assert!(text.contains("key.epoch == authority.connection_epoch()"));
}

#[test]
fn old_connection_message_cannot_affect_new_generation() {
    let text = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(text.contains("ConnectionAuthorityRejected"));
}

#[test]
fn daemon_restart_invalidates_old_connection_authority() {
    let text = source("crates/niralisd/src/server/connection_generation.rs");
    assert!(text.contains("NEXT_CONNECTION_EPOCH"));
    assert!(text.contains("DAEMON_GENERATION"));
}

#[test]
fn rejected_secret_frame_is_destroyed() {
    let text = source("crates/niralis-protocol/src/greeter.rs");
    assert!(text.contains("impl Drop for LoginSecret"));
}

#[test]
fn handler_requires_connection_binding_for_authenticated_login() {
    let text = source("crates/niralisd/src/handler/mod.rs");
    assert!(text.contains("handle_authenticated"));
    assert!(text.contains("LoginRequestBinding"));
}

#[test]
fn handler_rejects_login_without_authority_in_production() {
    let text = source("crates/niralisd/src/handler/mod.rs");
    assert!(text.contains("#[cfg(not(test))]"));
    assert!(text.contains("login requires an authenticated greeter connection"));
}

#[test]
fn secrets_have_no_debug_path() {
    let text = source("crates/niralis-protocol/src/greeter.rs");
    assert!(text.contains("LoginSecret([redacted])"));
    assert!(!text.contains("#[derive(Debug, Serialize, Deserialize)]\npub struct LoginSecret"));
}
