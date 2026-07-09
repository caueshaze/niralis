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
    #[error("worker binary is unavailable: {0}")]
    WorkerUnavailable(PathBuf),
}

pub type Result<T> = std::result::Result<T, NiralisdError>;
