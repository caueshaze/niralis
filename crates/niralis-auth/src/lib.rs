mod conversation;
mod mock;
mod pam;
#[cfg(test)]
mod tests;

pub use mock::{MockAuthenticatedTransaction, MockAuthenticator};
pub use pam::PamAuthenticator;
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
    #[error("authentication infrastructure failed")]
    InfrastructureFailed,
    #[error("authenticated identity unavailable")]
    AuthenticatedIdentityUnavailable,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthSessionError {
    #[error("failed to open authenticated session")]
    OpenFailed,
}

pub trait AuthenticatedTransaction: Send {
    fn user(&self) -> &AuthenticatedUser;

    fn open_session(&mut self) -> Result<(), AuthSessionError>;
}

pub trait Authenticator: Send + Sync {
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError>;
}

impl<T> Authenticator for Box<T>
where
    T: Authenticator + ?Sized,
{
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError> {
        (**self).authenticate(username, password)
    }
}
