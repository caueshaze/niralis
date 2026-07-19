#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorFixtureBoundaryMode {
    AlreadyEmpty,
    EmptyBoundary,
    RestartReconciles,
    WorkerAliveHandoff,
    PayloadRecovered,
    EbusyQuarantine,
    PopulatedThenRecovered,
    Replacement,
    BusLoss,
    Timeout,
    UnknownScope,
    UnknownScopeKnownSeat,
    ScopeRecordConflict,
    SystemdOwnerBeforeKill,
    SystemdOwnerDuringKill,
    SystemdOwnerBeforeProof,
    LogindOwnerBeforeTerminate,
    LogindOwnerDuringCleanup,
    LogindOwnerBeforeAbsence,
}
#[derive(Debug, Default)]
pub(crate) struct SupervisorFixtureCounters {
    pub(crate) prepares: std::sync::atomic::AtomicUsize,
    pub(crate) emergency_kills: std::sync::atomic::AtomicUsize,
    pub(crate) proofs: std::sync::atomic::AtomicUsize,
    pub(crate) unrefs: std::sync::atomic::AtomicUsize,
    pub(crate) logind_terminations: std::sync::atomic::AtomicUsize,
    pub(crate) vt_recoveries: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "supervisor-test-fixtures")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorFixtureSnapshot {
    pub prepares: usize,
    pub emergency_kills: usize,
    pub proofs: usize,
    pub unrefs: usize,
    pub logind_terminations: usize,
    pub vt_recoveries: usize,
}
