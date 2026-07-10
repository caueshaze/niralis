mod conversation;
mod mock;
mod pam;
mod pam_native;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PamSessionMetadata {
    pub session_type: PamSessionType,
    pub session_class: PamSessionClass,
    pub session_desktop: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamSessionType {
    Wayland,
    X11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamSessionClass {
    User,
    Greeter,
}

impl PamSessionMetadata {
    pub(crate) fn entries(&self) -> [String; 3] {
        let session_type = match self.session_type {
            PamSessionType::Wayland => "wayland",
            PamSessionType::X11 => "x11",
        };
        let session_class = match self.session_class {
            PamSessionClass::User => "user",
            PamSessionClass::Greeter => "greeter",
        };
        [
            format!("XDG_SESSION_TYPE={session_type}"),
            format!("XDG_SESSION_CLASS={session_class}"),
            format!("XDG_SESSION_DESKTOP={}", self.session_desktop),
        ]
    }
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

    fn open_session(&mut self, metadata: &PamSessionMetadata) -> Result<(), AuthSessionError>;
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
