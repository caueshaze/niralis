impl WorkerSessionLauncher {
    pub fn new(
        worker_path: PathBuf,
        session_child_path: PathBuf,
        session_probe_path: PathBuf,
        timeout: Duration,
        worker_environment: Vec<(String, String)>,
    ) -> Result<Self, SessionError> {
        if !worker_path.is_absolute()
            || !session_child_path.is_absolute()
            || !session_probe_path.is_absolute()
        {
            return Err(SessionError::InvalidWorkerPath);
        }
        Ok(Self {
            worker_path,
            session_child_path,
            session_probe_path,
            timeout,
            worker_environment,
            supervisor: Arc::new(WorkerSupervisor::new()),
            release_verifier: Arc::new(crate::SystemdPayloadScopeReleaseVerifier),
            #[cfg(any(feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
            fixture_recovery_provider: None,
        })
    }

    pub fn new_persistent(
        worker_path: PathBuf,
        session_child_path: PathBuf,
        session_probe_path: PathBuf,
        timeout: Duration,
        worker_environment: Vec<(String, String)>,
    ) -> Result<Self, SessionError> {
        if !worker_path.is_absolute()
            || !session_child_path.is_absolute()
            || !session_probe_path.is_absolute()
        {
            return Err(SessionError::InvalidWorkerPath);
        }
        let ledger = PersistentRecoveryLedger::open(DEFAULT_RECOVERY_DIR, DEFAULT_RECOVERY_LOCK)
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
            #[cfg(any(feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
            fixture_recovery_provider: None,
        })
    }

    #[cfg(any(test, feature = "integration-test-control"))]
    pub fn set_payload_scope_release_verifier_for_test(
        &mut self,
        verifier: Arc<dyn crate::PayloadScopeReleaseVerifier>,
    ) {
        self.release_verifier = verifier;
    }

    #[cfg(any(feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    pub fn use_supervisor_test_fixture_for_test(&mut self) {
        self.use_supervisor_test_fixture_mode_for_test(
            SupervisorFixtureBoundaryMode::AlreadyEmpty,
            true,
        );
    }

    #[cfg(any(feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    pub fn use_supervisor_test_fixture_mode_for_test(
        &mut self,
        mode: SupervisorFixtureBoundaryMode,
        logind_already_gone: bool,
    ) {
        let mut provider = SupervisorFixtureRecoveryProvider::successful();
        provider.mode = mode;
        provider.logind_already_gone = logind_already_gone;
        let provider = Arc::new(provider);
        self.supervisor = Arc::new(WorkerSupervisor::new_with_recovery_provider(
            provider.clone(),
        ));
        self.fixture_recovery_provider = Some(provider);
    }

    #[cfg(feature = "supervisor-test-fixtures")]
    pub fn register_supervisor_fixture_payload_members_for_test(
        &self,
        members: &[u32],
    ) -> Result<(), SessionError> {
        let provider = self
            .fixture_recovery_provider
            .as_ref()
            .ok_or(SessionError::WorkerProtocolFailed)?;
        let mut registered = provider
            .payload_members
            .lock()
            .map_err(|_| SessionError::WorkerIoFailed)?;
        registered.clear();
        registered.extend_from_slice(members);
        Ok(())
    }

    #[cfg(feature = "supervisor-test-fixtures")]
    pub fn arm_supervisor_fixture_prepare_gate_for_test(&self) -> Result<(), SessionError> {
        use std::sync::atomic::Ordering;
        let provider = self
            .fixture_recovery_provider
            .as_ref()
            .ok_or(SessionError::WorkerProtocolFailed)?;
        provider.prepare_gate_enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(feature = "supervisor-test-fixtures")]
    pub fn release_supervisor_fixture_prepare_gate_for_test(&self) -> Result<(), SessionError> {
        let provider = self
            .fixture_recovery_provider
            .as_ref()
            .ok_or(SessionError::WorkerProtocolFailed)?;
        signal_fixture_completion(&provider.prepare_gate);
        Ok(())
    }

    #[cfg(feature = "supervisor-test-fixtures")]
    pub fn wait_for_supervisor_fixture_recovery_for_test(
        &self,
        timeout: Duration,
    ) -> Result<SupervisorFixtureSnapshot, SessionError> {
        use std::sync::atomic::Ordering;
        let provider = self
            .fixture_recovery_provider
            .as_ref()
            .ok_or(SessionError::WorkerProtocolFailed)?;
        let mut descriptor = libc::pollfd {
            fd: provider.completion_event.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                timeout.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if result <= 0 || descriptor.revents & libc::POLLIN == 0 {
            return Err(SessionError::WorkerTimedOut);
        }
        let mut value = 0u64;
        let _ = unsafe {
            libc::read(
                provider.completion_event.as_raw_fd(),
                (&mut value as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        Ok(SupervisorFixtureSnapshot {
            prepares: provider.counters.prepares.load(Ordering::SeqCst),
            emergency_kills: provider.counters.emergency_kills.load(Ordering::SeqCst),
            proofs: provider.counters.proofs.load(Ordering::SeqCst),
            unrefs: provider.counters.unrefs.load(Ordering::SeqCst),
            logind_terminations: provider
                .counters
                .logind_terminations
                .load(Ordering::SeqCst),
            vt_recoveries: provider.counters.vt_recoveries.load(Ordering::SeqCst),
        })
    }

    pub fn worker_path(&self) -> &Path {
        &self.worker_path
    }

    pub fn terminate_session(&self, session: StartedSession) -> Result<(), SessionError> {
        self.supervisor.terminate(session)
    }

    #[cfg(any(test, feature = "integration-test-control"))]
    pub fn terminate_runtime_session_for_test(
        &self,
        runtime_id: RuntimeSessionId,
    ) -> Result<(), SessionError> {
        self.supervisor.terminate_runtime(runtime_id)
    }

    pub fn shutdown_sessions(&self) {
        let _ = self
            .supervisor
            .sender
            .send(WorkerSupervisorMessage::Shutdown);
    }

    pub fn start_pam_session(
        &self,
        request: SessionRequest,
        launch_plan: crate::SessionExecPlan,
        pam_service: String,
        password: WorkerSecret,
    ) -> Result<StartedSession, SessionError> {
        self.start_worker(
            WorkerRequest::PamSession {
                request: request.clone(),
                launch_plan,
                pam_service,
                password,
                session_child_path: self.session_child_path.clone(),
                session_probe_path: self.session_probe_path.clone(),
                control_path: PathBuf::new(),
                worker_id: String::new(),
                launcher_pid: 0,
            },
            expected_started_session(&request),
            true,
        )
        .map(|(session, _)| session)
    }

    #[cfg(any(test, feature = "integration-test-control"))]
    pub fn start_pam_session_for_test(
        &self,
        request: SessionRequest,
        launch_plan: crate::SessionExecPlan,
        pam_service: String,
        password: WorkerSecret,
    ) -> Result<(StartedSession, RuntimeSessionId), SessionError> {
        self.start_worker(
            WorkerRequest::PamSession {
                request: request.clone(),
                launch_plan,
                pam_service,
                password,
                session_child_path: self.session_child_path.clone(),
                session_probe_path: self.session_probe_path.clone(),
                control_path: PathBuf::new(),
                worker_id: String::new(),
                launcher_pid: 0,
            },
            expected_started_session(&request),
            true,
        )
    }

}
