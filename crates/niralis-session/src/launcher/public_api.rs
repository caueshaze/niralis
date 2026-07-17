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
        })
    }

    #[cfg(any(test, feature = "integration-test-control"))]
    pub fn set_payload_scope_release_verifier_for_test(
        &mut self,
        verifier: Arc<dyn crate::PayloadScopeReleaseVerifier>,
    ) {
        self.release_verifier = verifier;
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
