use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionError {
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("authenticated session failed")]
    AuthenticatedSessionFailed,
    #[error("invalid worker path")]
    InvalidWorkerPath,
    #[error("worker spawn failed")]
    WorkerSpawnFailed,
    #[error("worker io failed")]
    WorkerIoFailed,
    #[error("worker protocol failed")]
    WorkerProtocolFailed,
    #[error("worker timed out")]
    WorkerTimedOut,
    #[error("worker rejected request")]
    WorkerRejected,
    #[error("session start failed")]
    StartFailed,
}
