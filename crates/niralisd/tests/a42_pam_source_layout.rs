use std::fs;
use std::path::PathBuf;

fn source(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = root.parent().and_then(|path| path.parent()).unwrap();
    fs::read_to_string(workspace.join(path)).unwrap()
}

#[test]
fn pam_prompt_handling_requires_conversation_authority() {
    let text = source("crates/niralis-session/src/launcher/pam_prompt.rs");
    assert!(text.contains("pam_authority"));
    assert!(text.contains("accept_wire_prompt"));
    assert!(text.contains("accept_wire_response"));
}

#[test]
fn pam_response_correlation_is_not_request_id_only() {
    let text = source("crates/niralis-session/src/launcher/pam_prompt.rs");
    for field in [
        "connection_id",
        "connection_epoch",
        "transaction_id",
        "conversation_id",
        "prompt_id",
        "sequence",
        "style",
    ] {
        assert!(
            text.contains(&format!("response.{field}")),
            "missing response identity {field}"
        );
    }
}

#[test]
fn pam_secret_response_is_not_clonable_or_debuggable() {
    let protocol = source("crates/niralis-protocol/src/pam.rs");
    let worker = source("crates/niralis-session/src/protocol/worker_messages/variants.rs");
    assert!(protocol.contains("PamPromptResponse::Secret([redacted])"));
    assert!(!worker.contains("enum WorkerControlRequest {\n    Clone"));
}

#[test]
fn pam_public_failure_hides_raw_pam_details() {
    let auth = source("crates/niralis-auth/src/lib.rs");
    let handler = source("crates/niralisd/src/handler/login.rs");
    assert!(auth.contains("#[error(\"login failed\")]"));
    assert!(handler.contains("login_failed()"));
    assert!(!handler.contains("pam_status"));
}

#[test]
fn pam_reconnect_path_never_reuses_old_conversation() {
    let authority = format!(
        "{}\n{}",
        source("crates/niralis-session/src/pam_conversation.rs"),
        source("crates/niralis-session/src/pam_wire.rs")
    );
    let transport = source("crates/niralisd/src/server/client_protocol.rs");
    assert!(authority.contains("connection_epoch"));
    assert!(authority.contains("response.connection_epoch"));
    assert!(authority.contains("response.request_id"));
    assert!(transport.contains("next_connection_authority"));
}

#[test]
fn pam_success_consumes_authority_before_commit() {
    let transaction = source("crates/niralis-session/src/launcher/login_transaction.rs");
    let completion = source("crates/niralis-session/src/launcher/launch_completion.rs");
    assert!(transaction.contains("consume_authenticated_conversation"));
    assert!(completion.contains("consume_authenticated_conversation()?"));
    assert!(
        completion
            .find("consume_authenticated_conversation()?")
            .unwrap()
            < completion.find("attempt.finish();").unwrap()
    );
}

#[test]
fn pam_failure_consumes_authority_as_failed_before_rollback() {
    let transaction = source("crates/niralis-session/src/launcher/login_transaction.rs");
    let guards = source("crates/niralis-session/src/launcher/contracts/guards.rs");
    assert!(transaction.contains("consume_failed_conversation"));
    assert!(transaction.contains("conversation.fail()"));
    assert!(guards.contains("transaction.consume_failed_conversation()"));
}
