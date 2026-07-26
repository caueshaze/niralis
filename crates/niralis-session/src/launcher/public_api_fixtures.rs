pub struct PersistentSupervisorFixtureOptions {
    pub worker_path: PathBuf,
    pub session_child_path: PathBuf,
    pub session_probe_path: PathBuf,
    pub timeout: Duration,
    pub worker_environment: Vec<(String, String)>,
    pub recovery_dir: PathBuf,
    pub recovery_lock: PathBuf,
    pub mode: SupervisorFixtureBoundaryMode,
}

impl WorkerSessionLauncher {
    /// Starts the normal persistent launcher against a fixture-only physical
    /// smoke ledger. The caller must complete the PreviousBoot preflight
    /// before invoking this constructor.
    pub fn new_persistent_with_physical_previous_boot_smoke(
        worker_path: PathBuf,
        session_child_path: PathBuf,
        session_probe_path: PathBuf,
        timeout: Duration,
        worker_environment: Vec<(String, String)>,
        smoke: &PhysicalPreviousBootSmoke,
    ) -> Result<Self, SessionError> {
        smoke
            .assert_previous_boot_ready()
            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
        let ledger = PersistentRecoveryLedger::open(
            smoke.paths().recovery_dir(),
            smoke.paths().recovery_lock(),
        )
        .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
        Ok(Self {
            worker_path,
            session_child_path,
            session_probe_path,
            timeout,
            worker_environment,
            supervisor: Arc::new(WorkerSupervisor::new_with_persistent_ledger(
                Arc::new(LinuxSupervisorRecoveryProvider),
                ledger,
            )),
            release_verifier: Arc::new(crate::SystemdPayloadScopeReleaseVerifier),
            fixture_inherited_supervisor_control: false,
            fixture_supervisor_transport: false,
            fixture_recovery_provider: None,
        })
    }

    pub fn new_persistent_supervisor_fixture_for_test(
        options: PersistentSupervisorFixtureOptions,
    ) -> Result<Self, SessionError> {
        let PersistentSupervisorFixtureOptions {
            worker_path,
            session_child_path,
            session_probe_path,
            timeout,
            worker_environment,
            recovery_dir,
            recovery_lock,
            mode,
        } = options;
        let ledger = PersistentRecoveryLedger::open(&recovery_dir, recovery_lock)
            .map_err(|_| SessionError::PersistentRecoveryUnavailable)?;
        let mut provider = SupervisorFixtureRecoveryProvider::successful();
        provider.mode = mode;
        provider.operation_log = recovery_dir
            .parent()
            .map(|path| path.join("operations.log"));
        let provider = Arc::new(provider);
        Ok(Self {
            worker_path,
            session_child_path,
            session_probe_path,
            timeout,
            worker_environment,
            supervisor: Arc::new(WorkerSupervisor::new_with_persistent_ledger(provider, ledger)),
            release_verifier: Arc::new(crate::SystemdPayloadScopeReleaseVerifier),
            fixture_supervisor_transport: false,
            fixture_inherited_supervisor_control: false,
            fixture_recovery_provider: None,
        })
    }
}
