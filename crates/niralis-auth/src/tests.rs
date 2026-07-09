use crate::conversation::SilentPasswordConversation;
use crate::pam::authenticated_user_from_pam;
use crate::{AuthError, Authenticator, MockAuthenticator, PamAuthenticator};

#[test]
fn accepts_mock_user_transaction() {
    let auth = MockAuthenticator;

    let mut transaction = auth
        .authenticate("test", "test")
        .expect("mock credentials should authenticate");

    assert_eq!(transaction.user().username, "test");
    assert_eq!(transaction.user().display_name, "Test User");
    transaction
        .open_session()
        .expect("mock transaction should allow opening session");
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

#[test]
fn uses_pam_username_as_authenticated_identity() {
    let user = authenticated_user_from_pam("canonical-user".to_owned());

    assert_eq!(user.username, "canonical-user");
    assert_eq!(user.display_name, "canonical-user");
}
