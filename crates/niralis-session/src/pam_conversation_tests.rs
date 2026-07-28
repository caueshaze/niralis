use crate::pam_conversation::*;
use niralis_protocol::{
    LoginSecret, PamConversationId, PamMessageStyle, PamPromptId, PamPromptResponse,
};
use std::time::{Duration, Instant};
pub(crate) fn authority() -> PamConversationAuthority {
    PamConversationAuthority::issue(
        "tx-1".into(),
        7,
        "life-1".into(),
        "seat0".into(),
        3,
        "conn-1".into(),
        9,
        11,
        "worker-1".into(),
        PamConversationId::new_for_wire("conv-1".into()),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap()
}
#[test]
fn pam_conversation_requires_exact_login_transaction() {
    assert!(!authority()
        .matches_transaction("foreign", 7, "life-1", "seat0", 3, "conn-1", 9, "worker-1"));
}
#[test]
fn pam_conversation_requires_exact_greeter_connection() {
    assert!(
        !authority().matches_transaction("tx-1", 7, "life-1", "seat0", 3, "conn-2", 9, "worker-1")
    );
}
#[test]
fn prompt_echo_off_accepts_only_secret_response() {
    let p = authority()
        .prompt(
            PamPromptId(1),
            1,
            PamMessageStyle::PromptEchoOff,
            "Password".into(),
        )
        .unwrap();
    assert!(p
        .respond(
            "tx-1",
            "conn-1",
            9,
            "worker-1",
            PamPromptId(1),
            PamMessageStyle::PromptEchoOff,
            PamPromptResponse::Secret(LoginSecret::new("secret".into()))
        )
        .is_ok());
}
#[test]
fn prompt_echo_on_rejects_secret_style_mismatch() {
    let p = authority()
        .prompt(
            PamPromptId(1),
            1,
            PamMessageStyle::PromptEchoOn,
            "User".into(),
        )
        .unwrap();
    assert!(p
        .respond(
            "tx-1",
            "conn-1",
            9,
            "worker-1",
            PamPromptId(1),
            PamMessageStyle::PromptEchoOn,
            PamPromptResponse::Secret(LoginSecret::new("secret".into()))
        )
        .is_err());
}
#[test]
fn informational_message_accepts_no_response() {
    let p = authority()
        .prompt(
            PamPromptId(1),
            1,
            PamMessageStyle::Informational,
            "notice".into(),
        )
        .unwrap();
    assert!(p
        .respond(
            "tx-1",
            "conn-1",
            9,
            "worker-1",
            PamPromptId(1),
            PamMessageStyle::Informational,
            PamPromptResponse::None
        )
        .is_ok());
}
#[test]
fn unknown_pam_style_is_fail_closed() {
    let p = authority()
        .prompt(PamPromptId(1), 1, PamMessageStyle::Error, "error".into())
        .unwrap();
    assert!(p
        .respond(
            "tx-1",
            "conn-1",
            9,
            "worker-1",
            PamPromptId(1),
            PamMessageStyle::PromptEchoOff,
            PamPromptResponse::None
        )
        .is_err());
}
#[test]
fn stale_prompt_response_is_rejected() {
    let p = authority()
        .prompt(
            PamPromptId(1),
            1,
            PamMessageStyle::PromptEchoOn,
            "User".into(),
        )
        .unwrap();
    assert!(p
        .respond(
            "tx-1",
            "conn-1",
            9,
            "worker-1",
            PamPromptId(2),
            PamMessageStyle::PromptEchoOn,
            PamPromptResponse::Text("user".into())
        )
        .is_err());
}
#[test]
fn duplicate_response_is_rejected_by_single_use_ownership() {
    let p = authority()
        .prompt(
            PamPromptId(1),
            1,
            PamMessageStyle::PromptEchoOn,
            "User".into(),
        )
        .unwrap();
    let (a, _) = p
        .respond(
            "tx-1",
            "conn-1",
            9,
            "worker-1",
            PamPromptId(1),
            PamMessageStyle::PromptEchoOn,
            PamPromptResponse::Text("user".into()),
        )
        .unwrap();
    assert!(a
        .prompt(
            PamPromptId(1),
            1,
            PamMessageStyle::PromptEchoOn,
            "User".into()
        )
        .is_err());
}
#[test]
fn deadline_destroys_conversation() {
    let a = PamConversationAuthority::issue(
        "tx".into(),
        1,
        "life".into(),
        "seat".into(),
        1,
        "conn".into(),
        1,
        1,
        "worker".into(),
        PamConversationId::new_for_wire("c".into()),
        Instant::now() - Duration::from_secs(1),
    )
    .unwrap();
    assert!(a
        .prompt(
            PamPromptId(1),
            1,
            PamMessageStyle::PromptEchoOff,
            "p".into()
        )
        .is_err());
}
