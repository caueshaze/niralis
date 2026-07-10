use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NiralisdError {
    #[error("failed to read config {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ipc json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid socket path: {0}")]
    InvalidSocketPath(PathBuf),
    #[error("invalid worker path: {0}")]
    InvalidWorkerPath(PathBuf),
    #[error("invalid worker timeout: {0}")]
    InvalidWorkerTimeout(u64),
    #[error("worker binary is unavailable: {0}")]
    WorkerUnavailable(PathBuf),
    #[error("worker binary is untrusted: {0}")]
    WorkerUntrusted(PathBuf),
    #[error("invalid session child path: {0}")]
    InvalidSessionChildPath(PathBuf),
    #[error("session child is unavailable: {0}")]
    SessionChildUnavailable(PathBuf),
    #[error("session child is untrusted: {0}")]
    SessionChildUntrusted(PathBuf),
    #[error("invalid session probe path: {0}")]
    InvalidSessionProbePath(PathBuf),
    #[error("session probe is unavailable: {0}")]
    SessionProbeUnavailable(PathBuf),
    #[error("session probe is untrusted: {0}")]
    SessionProbeUntrusted(PathBuf),
    #[error("PAM authentication requires the worker session launcher")]
    InvalidAuthLauncherCombination,
}

pub type Result<T> = std::result::Result<T, NiralisdError>;
