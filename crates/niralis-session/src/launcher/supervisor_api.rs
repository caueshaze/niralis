impl WorkerSupervisor {
    fn recovery_admin(
        &self,
        request: crate::RecoveryAdminRequest,
    ) -> Result<crate::RecoveryAdminResponse, SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::RecoveryAdmin { request, result })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }
    fn reserve_seat(&self, lifecycle_id: &str) -> Result<supervisor_loop::admission::AdmissionLease, SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::ReserveSeat {
                lifecycle_id: lifecycle_id.to_owned(),
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn cancel_admission(&self, lease: supervisor_loop::admission::AdmissionRollbackLease) {
        let _ = self
            .sender
            .send(WorkerSupervisorMessage::CancelAdmission { lease });
    }

    fn begin_pending(
        &self,
        lease: supervisor_loop::admission::AdmissionLease,
        worker_pid: u32,
        launcher_pid: u32,
        session: StartedSession,
        child: Arc<Mutex<Child>>,
    ) -> Result<supervisor_loop::admission::PendingLifecycleLease, SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::BeginPending {
                lease,
                worker_pid,
                launcher_pid,
                session,
                child,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn record_prepared_scope(
        &self,
        worker_id: &str,
        worker_pid: u32,
        session_pid: u32,
        identity: crate::PayloadScopeIdentity,
        registration_nonce: String,
    ) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::RecordPreparedScope {
                worker_id: worker_id.to_owned(),
                worker_pid,
                session_pid,
                identity,
                registration_nonce,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn mark_payload_registered(
        &self,
        worker_id: &str,
        worker_pid: u32,
    ) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::MarkPayloadRegistered {
                worker_id: worker_id.to_owned(),
                worker_pid,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn begin_release(&self, request: ReleaseRequest) -> Result<ReleaseToken, SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::BeginRelease { request, result })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn complete_release(
        &self,
        token: ReleaseToken,
        verification: crate::ScopeReleaseVerification,
    ) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::CompleteRelease {
                token,
                verification,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    fn abort_pending(
        &self,
        lease: supervisor_loop::admission::PendingLifecycleLease,
        expected_clean: bool,
        worker_exit_status: Option<ExitStatus>,
    ) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::AbortPending {
                lease,
                expected_clean,
                worker_exit_status,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(7))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    #[allow(clippy::too_many_arguments)]
    fn register(
        &self,
        admission_transaction: login_transaction::PendingLaunchTransaction,
        child: Arc<Mutex<Child>>,
        supervisor_channel: UnixStream,
        #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
        fixture_supervisor_transport: Option<worker_attempt::FixtureSupervisorTransportHandle>,
        #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
        fixture_inherited_supervisor_control: bool,
        session: StartedSession,
        session_pid: u32,
        session_pgid: u32,
        worker_id: String,
        logind_session_id: crate::LogindSessionId,
        payload_scope: crate::PayloadScopeIdentity,
        registration_nonce: String,
        control_path: PathBuf,
        control_dir: TempDir,
    ) -> Result<RuntimeSessionId, SessionError> {
        if child
            .lock()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .try_wait()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .is_some()
        {
            return Err(SessionError::WorkerExitedAfterStart);
        }
        let runtime_id = RuntimeSessionId::new(worker_id.clone());
        let (result, receiver) = mpsc::channel();
        match self.sender.send(WorkerSupervisorMessage::Register {
            admission_transaction: Box::new(admission_transaction),
            runtime_id: runtime_id.clone(),
            supervisor_channel,
            #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
            fixture_supervisor_transport,
            #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
            fixture_inherited_supervisor_control,
            session,
            session_pid,
            session_pgid,
            worker_id,
            logind_session_id,
            payload_scope,
            registration_nonce,
            control_path,
            control_dir,
            control_sender: self.sender.clone(),
            result,
        }) {
            Ok(()) => {
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| SessionError::WorkerIoFailed)??;
                Ok(runtime_id)
            }
            Err(_) => Err(SessionError::WorkerIoFailed),
        }
    }

    fn terminate(&self, session: StartedSession) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::Terminate {
                session,
                runtime_id: None,
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }

    #[cfg(any(test, feature = "integration-test-control"))]
    fn terminate_runtime(&self, runtime_id: RuntimeSessionId) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::Terminate {
                session: StartedSession {
                    username: String::new(),
                    session: niralis_protocol::SessionInfo {
                        id: String::new(),
                        name: String::new(),
                        kind: niralis_protocol::SessionKind::Wayland,
                    },
                },
                runtime_id: Some(runtime_id),
                result,
            })
            .map_err(|_| SessionError::WorkerIoFailed)?;
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| SessionError::WorkerIoFailed)?
    }
}
