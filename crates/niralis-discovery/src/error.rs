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
}
