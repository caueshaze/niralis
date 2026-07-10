use crate::conversation::SilentPasswordConversation;
use crate::{
    AuthError, Authenticator, MockAuthenticator, PamAuthenticator, PamSessionClass,
    PamSessionMetadata, PamSessionType, SeatId, VirtualTerminalId,
};

#[test]
fn pam_owned_runtime_path_rejects_empty_nul_and_oversized_values() {
    assert!(crate::PamUnixPath::new(Vec::new()).is_err());
    assert!(crate::PamUnixPath::new(vec![0]).is_err());
    assert!(crate::PamUnixPath::new(vec![b'a'; 4097]).is_err());
}

#[test]
fn accepts_mock_user_transaction() {
    let auth = MockAuthenticator;

    let mut transaction = auth
        .authenticate("test", "test")
        .expect("mock credentials should authenticate");

    assert_eq!(transaction.user().username, "test");
    assert_eq!(transaction.user().display_name, "Test User");
    transaction
        .open_session(&PamSessionMetadata {
            session_type: PamSessionType::Wayland,
            session_class: PamSessionClass::User,
            session_desktop: "niri".to_owned(),
            seat: None,
            vtnr: None,
            tty: None,
        })
        .expect("mock transaction should allow opening session");
}

#[test]
fn session_metadata_emits_owned_seat_and_vt_after_core_fields() {
    let metadata = PamSessionMetadata {
        session_type: PamSessionType::Wayland,
        session_class: PamSessionClass::User,
        session_desktop: "niri".to_owned(),
        seat: Some(SeatId::new("seat0".to_owned()).unwrap()),
        vtnr: Some(VirtualTerminalId::new(7).unwrap()),
        tty: Some("/dev/tty7".to_owned()),
    };
    assert_eq!(
        metadata.entries(),
        vec![
            "XDG_SESSION_TYPE=wayland",
            "XDG_SESSION_CLASS=user",
            "XDG_SESSION_DESKTOP=niri",
            "XDG_SEAT=seat0",
            "XDG_VTNR=7",
        ]
    );
}

#[test]
fn invalid_seat_and_vt_values_are_rejected() {
    assert!(SeatId::new(String::new()).is_none());
    assert!(VirtualTerminalId::new(0).is_none());
    assert!(VirtualTerminalId::new(64).is_none());
}

#[test]
fn rejects_invalid_login_with_generic_error() {
    let auth = MockAuthenticator;

    let error = match auth.authenticate("test", "wrong-password") {
        Ok(_) => panic!("invalid credentials should fail"),
        Err(error) => error,
    };

    assert_eq!(error, AuthError::LoginFailed);
    assert!(!error.to_string().contains("wrong-password"));
}

#[test]
fn auth_error_variants_preserve_semantics() {
    assert_eq!(
        AuthError::InfrastructureFailed.to_string(),
        "authentication infrastructure failed"
    );
    assert_eq!(
        AuthError::AuthenticatedIdentityUnavailable.to_string(),
        "authenticated identity unavailable"
    );
}

#[test]
fn conversation_clears_password() {
    let mut conversation = SilentPasswordConversation::new();
    conversation.set_credentials("test".to_owned(), "secret".to_owned());

    conversation.clear_password();

    assert!(conversation.password_is_cleared());
}

#[test]
fn constructs_pam_authenticator() {
    let auth = PamAuthenticator::new("niralis");

    assert_eq!(auth.service(), "niralis");
}
