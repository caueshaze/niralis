mod nss;
#[cfg(test)]
mod tests;

use std::path::PathBuf;

use thiserror::Error;

pub use nss::NssUnixIdentityResolver;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixIdentity {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityError {
    #[error("user not found")]
    NotFound,
    #[error("invalid username")]
    InvalidUsername,
    #[error("invalid canonical username")]
    InvalidCanonicalUsername,
    #[error("identity lookup failed")]
    LookupFailed,
    #[error("identity lookup buffer limit exceeded")]
    BufferLimitExceeded,
}

pub trait UnixIdentityResolver: Send + Sync {
    fn resolve(&self, username: &str) -> Result<UnixIdentity, IdentityError>;
}
