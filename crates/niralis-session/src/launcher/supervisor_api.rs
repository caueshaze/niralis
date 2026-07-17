impl WorkerSupervisor {
    fn begin_pending(&self, worker_id: &str, worker_pid: u32) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::BeginPending {
                worker_id: worker_id.to_owned(),
                worker_pid,
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
        identity: crate::PayloadScopeIdentity,
        registration_nonce: String,
    ) -> Result<(), SessionError> {
        let (result, receiver) = mpsc::channel();
        self.sender
            .send(WorkerSupervisorMessage::RecordPreparedScope {
                worker_id: worker_id.to_owned(),
                worker_pid,
                identity,
                registration_nonce,
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

    fn abort_pending(&self, worker_id: &str) {
        let _ = self.sender.send(WorkerSupervisorMessage::AbortPending {
            worker_id: worker_id.to_owned(),
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn register(
        &self,
        child: Child,
        supervisor_channel: UnixStream,
        session: StartedSession,
        session_pid: u32,
        session_pgid: u32,
        worker_id: String,
        logind_session_id: crate::LogindSessionId,
        payload_scope: crate::PayloadScopeIdentity,
        control_path: PathBuf,
        control_dir: TempDir,
    ) -> Result<RuntimeSessionId, SessionError> {
        let mut child = child;
        if child
            .try_wait()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .is_some()
        {
            return Err(SessionError::WorkerExitedAfterStart);
        }
        let runtime_id = RuntimeSessionId::new(worker_id.clone());
        let (result, receiver) = mpsc::channel();
        match self.sender.send(WorkerSupervisorMessage::Register {
            runtime_id: runtime_id.clone(),
            child,
            supervisor_channel,
            session,
            session_pid,
            session_pgid,
            worker_id,
            logind_session_id,
            payload_scope,
            control_path,
            control_dir,
            result,
        }) {
            Ok(()) => {
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| SessionError::WorkerIoFailed)??;
                Ok(runtime_id)
            }
            Err(error) => {
                if let WorkerSupervisorMessage::Register { mut child, .. } = error.0 {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(SessionError::WorkerIoFailed)
            }
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
