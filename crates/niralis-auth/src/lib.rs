use std::ffi::{CStr, CString};

use pam::{Client, Conversation};
use thiserror::Error;
use tracing::{debug, trace};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    #[error("login failed")]
    LoginFailed,
}

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, username: &str, password: &str) -> Result<AuthenticatedUser, AuthError>;
    fn users(&self) -> Result<Vec<AuthenticatedUser>, AuthError>;
}

impl<T> Authenticator for Box<T>
where
    T: Authenticator + ?Sized,
{
    fn authenticate(&self, username: &str, password: &str) -> Result<AuthenticatedUser, AuthError> {
        (**self).authenticate(username, password)
    }

    fn users(&self) -> Result<Vec<AuthenticatedUser>, AuthError> {
        (**self).users()
    }
}

#[derive(Debug, Default)]
pub struct MockAuthenticator;

impl Authenticator for MockAuthenticator {
    fn authenticate(&self, username: &str, password: &str) -> Result<AuthenticatedUser, AuthError> {
        if username == "test" && password == "test" {
            Ok(AuthenticatedUser {
                username: username.to_owned(),
                display_name: "Test User".to_owned(),
            })
        } else {
            Err(AuthError::LoginFailed)
        }
    }

    fn users(&self) -> Result<Vec<AuthenticatedUser>, AuthError> {
        Ok(vec![AuthenticatedUser {
            username: "test".to_owned(),
            display_name: "Test User".to_owned(),
        }])
    }
}

#[derive(Debug, Clone)]
pub struct PamAuthenticator {
    service: String,
}

impl PamAuthenticator {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }
}

impl Authenticator for PamAuthenticator {
    fn authenticate(&self, username: &str, password: &str) -> Result<AuthenticatedUser, AuthError> {
        let mut client =
            Client::with_conversation(&self.service, SilentPasswordConversation::new()).map_err(
                |error| {
                    debug!(service = %self.service, ?error, "failed to initialize PAM client");
                    AuthError::LoginFailed
                },
            )?;

        client
            .conversation_mut()
            .set_credentials(username.to_owned(), password.to_owned());

        client.authenticate().map_err(|error| {
            debug!(service = %self.service, username = %username, ?error, "PAM authentication failed");
            AuthError::LoginFailed
        })?;

        Ok(AuthenticatedUser {
            username: username.to_owned(),
            display_name: username.to_owned(),
        })
    }

    fn users(&self) -> Result<Vec<AuthenticatedUser>, AuthError> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Default)]
struct SilentPasswordConversation {
    username: String,
    password: String,
}

impl SilentPasswordConversation {
    fn new() -> Self {
        Self::default()
    }

    fn set_credentials(&mut self, username: String, password: String) {
        self.username = username;
        self.password = password;
    }
}

impl Conversation for SilentPasswordConversation {
    fn prompt_echo(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.username.clone()).map_err(|_| ())
    }

    fn prompt_blind(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.password.clone()).map_err(|_| ())
    }

    fn info(&mut self, _msg: &CStr) {
        trace!("PAM sent an informational conversation message");
    }

    fn error(&mut self, _msg: &CStr) {
        trace!("PAM sent an error conversation message");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_mock_user() {
        let auth = MockAuthenticator;

        let user = auth
            .authenticate("test", "test")
            .expect("mock credentials should authenticate");

        assert_eq!(user.username, "test");
    }

    #[test]
    fn rejects_invalid_login_with_generic_error() {
        let auth = MockAuthenticator;

        let error = auth
            .authenticate("test", "wrong-password")
            .expect_err("invalid credentials should fail");

        assert_eq!(error.to_string(), "login failed");
        assert!(!error.to_string().contains("wrong-password"));
    }

    #[test]
    fn constructs_pam_authenticator() {
        let auth = PamAuthenticator::new("niralis");

        assert_eq!(auth.service(), "niralis");
    }
}
