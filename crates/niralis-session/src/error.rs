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
    #[error("worker exited after reporting startup")]
    WorkerExitedAfterStart,
    #[error("session seat is active, recovering, or quarantined")]
    SessionSeatUnavailable,
    #[error("session worker died and supervisor recovery is incomplete")]
    WorkerRecoveryIncomplete,
    #[error("session worker died and was recovered by the supervisor")]
    WorkerDiedAndWasRecovered,
    #[error("persistent recovery ledger is unavailable")]
    PersistentRecoveryUnavailable,
}
