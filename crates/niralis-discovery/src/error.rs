use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("failed to enumerate users")]
    UserEnumeration,
    #[error("failed to read desktop entry {path}: {source}")]
    ReadDesktopEntry {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("session source is untrusted: {path}")]
    UntrustedSessionSource { path: PathBuf },
    #[error("desktop entry is malformed: {path}")]
    MalformedDesktopEntry { path: PathBuf },
    #[error("session launch specification is invalid")]
    InvalidLaunchSpec,
}
