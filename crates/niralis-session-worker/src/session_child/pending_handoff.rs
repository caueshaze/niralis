
impl PendingExecHandoff for ProcessPendingExecHandoff {
    fn report(&self) -> &SessionChildReport {
        &self.report
    }

    fn authoritative_pidfd(&self) -> RawFd {
        self.pidfd.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }

    fn commit_exec(mut self: Box<Self>) -> Result<SessionChildReport, SessionChildError> {
        let deadline = Instant::now() + SESSION_CHILD_HANDSHAKE_TIMEOUT;
        self.attempt.send_commit(deadline)?;
        match self.attempt.wait_exec_status(deadline)? {
            ExecStatus::Success => {}
            ExecStatus::Failure(failure) => {
                warn!(stage = %failure.stage, errno = failure.errno, "final execve failed");
                return Err(SessionChildError::ExitFailed);
            }
        }
        if self
            .attempt
            .child
            .as_mut()
            .expect("child exists")
            .try_wait()
            .map_err(|_| SessionChildError::IoFailed)?
            .is_some()
        {
            return Err(SessionChildError::ExitFailed);
        }
        let pgid = self.report.process_identity.pgid;
        let pidfd = self.pidfd.take().ok_or(SessionChildError::IoFailed)?;
        let mut live_child = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?;
        let child = self.attempt.take_child();
        *live_child = Some(LiveSessionChild { child, pgid, pidfd });
        self.completed = true;
        Ok(self.report.clone())
    }

    fn abort(mut self: Box<Self>) -> Result<(), SessionChildError> {
        self.attempt.kill_and_reap();
        self.attempt.finish();
        self.completed = true;
        Ok(())
    }
}

impl Drop for ProcessPendingExecHandoff {
    fn drop(&mut self) {
        if !self.completed {
            warn!(
                pid = self.report.child_pid,
                "pending session exec handoff dropped without CommitExec; aborting probe"
            );
        }
        self.attempt.kill_and_reap();
        self.attempt.finish();
    }
}

impl ProcessSessionChildRunner {
    pub fn new(path: PathBuf) -> Result<Self, SessionChildError> {
        if !path.is_absolute() {
            return Err(SessionChildError::InvalidPath);
        }
        Ok(Self {
            path,
            terminal_fd: Arc::new(Mutex::new(None)),
            live_child: Arc::new(Mutex::new(None)),
        })
    }

    pub fn with_terminal(
        path: PathBuf,
        terminal_fd: Option<OwnedFd>,
    ) -> Result<Self, SessionChildError> {
        let runner = Self::new(path)?;
        *runner
            .terminal_fd
            .lock()
            .map_err(|_| SessionChildError::IoFailed)? = terminal_fd;
        Ok(runner)
    }
}

impl Drop for ProcessSessionChildRunner {
    fn drop(&mut self) {
        if let Ok(mut child) = self.live_child.lock() {
            if let Some(mut live) = child.take() {
                let _ = terminate_group(live.pgid, libc::SIGKILL);
                let _ = live.child.wait();
            }
        }
    }
}
