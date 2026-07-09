use thiserror::Error;

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
}
