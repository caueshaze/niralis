use crate::{
    AuthError, AuthSessionError, AuthenticatedTransaction, AuthenticatedUser, Authenticator,
    PamSessionEnvironment, PamUnixPath,
};

#[derive(Debug, Default)]
pub struct MockAuthenticator;

impl Authenticator for MockAuthenticator {
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError> {
        if username == "test" && password == "test" {
            Ok(Box::new(MockAuthenticatedTransaction {
                user: AuthenticatedUser {
                    username: username.to_owned(),
                    display_name: "Test User".to_owned(),
                },
            }))
        } else {
            Err(AuthError::LoginFailed)
        }
    }
}

#[derive(Debug)]
pub struct MockAuthenticatedTransaction {
    user: AuthenticatedUser,
}

impl AuthenticatedTransaction for MockAuthenticatedTransaction {
    fn user(&self) -> &AuthenticatedUser {
        &self.user
    }

    fn open_session(
        &mut self,
        _metadata: &crate::PamSessionMetadata,
    ) -> Result<(), AuthSessionError> {
        Ok(())
    }

    fn session_environment(&mut self) -> Result<PamSessionEnvironment, AuthSessionError> {
        Ok(PamSessionEnvironment {
            session_id: "mock-session".to_owned(),
            runtime_dir: PamUnixPath::new(b"/run/user/1000".to_vec())?,
            imported_locale: Vec::new(),
        })
    }
}
