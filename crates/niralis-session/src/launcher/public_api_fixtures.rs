impl WorkerSessionLauncher {
    pub fn new_persistent_supervisor_fixture_for_test(worker_path: PathBuf, session_child_path: PathBuf, session_probe_path: PathBuf, timeout: Duration, worker_environment: Vec<(String, String)>, recovery_dir: PathBuf, recovery_lock: PathBuf, mode: SupervisorFixtureBoundaryMode) -> Result<Self, SessionError> {
        let ledger = PersistentRecoveryLedger::open(&recovery_dir, recovery_lock).map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
        let mut provider = SupervisorFixtureRecoveryProvider::successful();
        provider.mode = mode;
        provider.operation_log = recovery_dir
            .parent()
            .map(|path| path.join("operations.log"));
        let provider = Arc::new(provider);
        Ok(Self { worker_path, session_child_path, session_probe_path, timeout, worker_environment, supervisor: Arc::new(WorkerSupervisor::new_with_persistent_ledger(provider, ledger)), release_verifier: Arc::new(crate::SystemdPayloadScopeReleaseVerifier), fixture_recovery_provider: None })
    }
}
