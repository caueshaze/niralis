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
    pub seat: Option<SeatId>,
    pub vtnr: Option<VirtualTerminalId>,
    pub tty: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PamUnixPath {
    pub bytes: Vec<u8>,
}

impl PamUnixPath {
    pub fn new(bytes: Vec<u8>) -> Result<Self, AuthSessionError> {
        if bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0) {
            return Err(AuthSessionError::EnvironmentInvalid);
        }
        Ok(Self { bytes })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PamSessionEnvironment {
    pub session_id: String,
    pub runtime_dir: PamUnixPath,
    pub imported_locale: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeatId(String);

impl SeatId {
    pub fn new(value: String) -> Option<Self> {
        (!value.is_empty() && value.len() <= 64 && !value.as_bytes().contains(&0))
            .then_some(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtualTerminalId(u32);

impl VirtualTerminalId {
    pub fn new(value: u32) -> Option<Self> {
        (value > 0 && value <= 63).then_some(Self(value))
    }

    pub fn number(self) -> u32 {
        self.0
    }
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
    pub(crate) fn entries(&self) -> Vec<String> {
        let session_type = match self.session_type {
            PamSessionType::Wayland => "wayland",
            PamSessionType::X11 => "x11",
        };
        let session_class = match self.session_class {
            PamSessionClass::User => "user",
            PamSessionClass::Greeter => "greeter",
        };
        let mut entries = vec![
            format!("XDG_SESSION_TYPE={session_type}"),
            format!("XDG_SESSION_CLASS={session_class}"),
            format!("XDG_SESSION_DESKTOP={}", self.session_desktop),
        ];
        if let Some(seat) = &self.seat {
            entries.push(format!("XDG_SEAT={}", seat.as_str()));
        }
        if let Some(vtnr) = self.vtnr {
            entries.push(format!("XDG_VTNR={}", vtnr.number()));
        }
        entries
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
    #[error("required PAM session environment is invalid")]
    EnvironmentInvalid,
    #[error("failed to close authenticated session")]
    CloseFailed,
}

pub trait AuthenticatedTransaction: Send {
    fn user(&self) -> &AuthenticatedUser;

    fn open_session(&mut self, metadata: &PamSessionMetadata) -> Result<(), AuthSessionError>;

    fn session_environment(&mut self) -> Result<PamSessionEnvironment, AuthSessionError>;

    fn close_session(&mut self) -> Result<(), AuthSessionError> {
        Ok(())
    }
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
