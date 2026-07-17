
impl SessionChildRunner for ProcessSessionChildRunner {
    fn run_child_until_ready(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<Box<dyn PendingExecHandoff>, SessionChildError> {
        let deadline = Instant::now() + SESSION_CHILD_HANDSHAKE_TIMEOUT;
        let request = SessionChildEnvelope {
            version: SESSION_CHILD_PROTOCOL_VERSION,
            message: SessionChildRequest::ApplyCredentials {
                canonical_username: expectation.canonical_username.clone(),
                session_id: expectation.session_id.clone(),
                credentials: SessionChildUnixCredentials::from(&expectation.target_credentials),
                runtime: expectation.runtime.clone(),
                terminal: expectation.terminal.clone(),
            },
        };
        let payload = serde_json::to_vec(&request).map_err(|_| SessionChildError::IoFailed)?;
        if payload.len() + 1 > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
            return Err(SessionChildError::ProtocolFailed);
        }
        let terminal_fd = self
            .terminal_fd
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?
            .take();
        let mut attempt = SessionChildAttempt::spawn(&self.path, payload, terminal_fd)?;
        let pid = attempt.child.as_ref().expect("child exists").id();
        let reader_result = attempt.wait_reader(deadline);
        if let Err(error) = &reader_result {
            match attempt.child.as_mut().expect("child exists").try_wait() {
                Ok(Some(status)) => {
                    warn!(
                        ?error,
                        ?status,
                        "session child exited before sending its ready response"
                    );
                }
                Ok(None) => {
                    warn!(
                        ?error,
                        "session child response read failed while the child remained alive"
                    );
                }
                Err(wait_error) => {
                    warn!(?error, errno = ?wait_error.raw_os_error(), wait_error = %wait_error, "could not inspect session child after its response read failed");
                }
            }
            attempt.kill_and_reap();
        }
        let bytes = reader_result?;
        let response: SessionChildEnvelope<SessionChildResponse> = parse_response(&bytes)?;
        if response.version != SESSION_CHILD_PROTOCOL_VERSION {
            return Err(SessionChildError::ProtocolFailed);
        }
        if let SessionChildResponse::Rejected { code } = &response.message {
            warn!(?code, "session child rejected its credential handoff");
            return Err(SessionChildError::ProtocolFailed);
        }
        let ready_status = attempt
            .child
            .as_mut()
            .expect("child exists")
            .try_wait()
            .map_err(|error| {
                warn!(errno = ?error.raw_os_error(), error = %error, "checking session child state after ready failed");
                SessionChildError::IoFailed
            })?;
        if let Some(status) = ready_status {
            if !status.success() {
                return Err(SessionChildError::ExitFailed);
            }
            return Err(SessionChildError::ExitFailed);
        }
        let report = validate_ready_response(response.message, &expectation, pid, true)?;
        let child = attempt.child.as_ref().expect("child exists");
        let pgid = report.process_identity.pgid;
        let pidfd = match open_pidfd(child.id()) {
            Some(pidfd) => pidfd,
            None => {
                attempt.kill_and_reap();
                return Err(SessionChildError::IoFailed);
            }
        };
        debug_assert_eq!(pgid, report.process_identity.pgid);
        Ok(Box::new(ProcessPendingExecHandoff {
            attempt,
            report,
            pidfd: Some(pidfd),
            live_child: self.live_child.clone(),
            completed: false,
        }))
    }

    fn wait_for_child(&self) -> Result<std::process::ExitStatus, SessionChildError> {
        let mut guard = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?;
        let mut live = guard.take().ok_or(SessionChildError::IoFailed)?;
        live.child.wait().map_err(|_| SessionChildError::IoFailed)
    }

    fn wait_for_child_or_control(
        &self,
        control_fd: Option<RawFd>,
    ) -> Result<SessionChildWaitEvent, SessionChildError> {
        let mut guard = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?;
        let live = guard.as_mut().ok_or(SessionChildError::IoFailed)?;
        let mut fds = [
            libc::pollfd {
                fd: live.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: control_fd.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let count = if control_fd.is_some() { 2 } else { 1 };
        let result = unsafe { libc::poll(fds.as_mut_ptr(), count, -1) };
        if result < 0 {
            return Err(SessionChildError::IoFailed);
        }
        if control_fd.is_some() && fds[1].revents & libc::POLLIN != 0 {
            return Ok(SessionChildWaitEvent::ControlReady);
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) == 0 {
            return Err(SessionChildError::IoFailed);
        }
        let mut live = guard.take().ok_or(SessionChildError::IoFailed)?;
        live.child
            .wait()
            .map(SessionChildWaitEvent::Exited)
            .map_err(|_| SessionChildError::IoFailed)
    }

    fn poll_child(&self) -> Result<Option<std::process::ExitStatus>, SessionChildError> {
        let mut guard = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?;
        let Some(live) = guard.as_mut() else {
            return Err(SessionChildError::IoFailed);
        };
        match live
            .child
            .try_wait()
            .map_err(|_| SessionChildError::IoFailed)?
        {
            Some(status) => {
                guard.take();
                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    fn authoritative_pidfd(&self) -> RawFd {
        self.live_child
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|live| live.pidfd.as_raw_fd()))
            .unwrap_or(-1)
    }

    fn terminate(&self, grace: Duration) -> Result<std::process::ExitStatus, SessionChildError> {
        // Legacy pre-Running/error-path cleanup. The production Running
        // coordinator never calls this method and never treats PGID as the
        // authoritative payload boundary.
        let mut live = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?
            .take()
            .ok_or(SessionChildError::IoFailed)?;
        let _ = terminate_group(live.pgid, libc::SIGTERM);
        info!(pgid = live.pgid, "session process group SIGTERM sent");
        let deadline = Instant::now() + grace;
        loop {
            if let Some(status) = live
                .child
                .try_wait()
                .map_err(|_| SessionChildError::IoFailed)?
            {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                info!(pgid = live.pgid, "session termination grace period expired");
                terminate_group(live.pgid, libc::SIGKILL)?;
                info!(pgid = live.pgid, "session process group SIGKILL sent");
                return live.child.wait().map_err(|_| SessionChildError::IoFailed);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn terminate_group(pgid: u32, signal: libc::c_int) -> Result<(), SessionChildError> {
    if pgid == 0 || pgid > libc::pid_t::MAX as u32 {
        return Err(SessionChildError::IoFailed);
    }
    let result = unsafe { libc::kill(-(pgid as libc::pid_t), signal) };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(SessionChildError::IoFailed)
    }
}
