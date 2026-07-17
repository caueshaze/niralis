impl SessionChildRunnerFactory for FixtureChildFactory {
    fn build(&self, _: &std::path::Path) -> Result<Box<dyn SessionChildRunner>, SessionChildError> {
        Ok(Box::new(FixtureChildRunner(self.0.clone())))
    }
}
struct FixtureChildRunner(Arc<FixtureState>);
struct FixturePending {
    state: Arc<FixtureState>,
    report: SessionChildReport,
    pidfd: Option<OwnedFd>,
    completed: bool,
}

impl SessionChildRunner for FixtureChildRunner {
    fn run_child_until_ready(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<Box<dyn PendingExecHandoff>, SessionChildError> {
        let (command_read, command_write) = pipe()?;
        let (ready_read, ready_write) = pipe()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(SessionChildError::IoFailed);
        }
        if pid == 0 {
            drop(command_write);
            drop(ready_read);
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                libc::setsid();
            }
            let signal_state_clean = crate::termination::restore_payload_signal_state().is_ok()
                && [libc::SIGTERM, libc::SIGINT, libc::SIGHUP]
                    .into_iter()
                    .all(signal_has_default_disposition);
            for fd in 3..1024 {
                if fd != command_read.as_raw_fd() && fd != ready_write.as_raw_fd() {
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
            let fd_hygiene = (3..1024).all(|fd| {
                fd == command_read.as_raw_fd()
                    || fd == ready_write.as_raw_fd()
                    || unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1
            });
            let member_pid = if self.0.mode == FixtureMode::LeaderExitRemainingMember {
                let member = unsafe { libc::fork() };
                if member < 0 {
                    unsafe { libc::_exit(2) }
                }
                if member == 0 {
                    loop {
                        unsafe { libc::pause() };
                    }
                }
                member as u32
            } else {
                0
            };
            let mut flags = [0_u8; 6];
            flags[0] = u8::from(signal_state_clean);
            flags[1] = u8::from(fd_hygiene);
            flags[2..].copy_from_slice(&member_pid.to_ne_bytes());
            unsafe {
                libc::write(ready_write.as_raw_fd(), flags.as_ptr().cast(), flags.len());
            }
            if member_pid != 0 {
                unsafe { libc::_exit(0) }
            }
            let mut byte = 0_u8;
            unsafe {
                libc::read(command_read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
            }
            unsafe { libc::_exit(0) }
        }
        drop(command_read);
        drop(ready_write);
        let mut flags = [0_u8; 6];
        if unsafe { libc::read(ready_read.as_raw_fd(), flags.as_mut_ptr().cast(), flags.len()) }
            != flags.len() as isize
        {
            return Err(SessionChildError::IoFailed);
        }
        if flags[0] == 1 {
            emit_fixture_event("PayloadSignalMaskRestored");
        }
        if flags[1] == 1 {
            emit_fixture_event("PayloadFdHygieneVerified");
        }
        let pid = pid as u32;
        emit_fixture_event(&format!("LeaderPid:{pid}"));
        let pidfd = open_pidfd(pid)?;
        *self.0.pid.lock().map_err(|_| SessionChildError::IoFailed)? = Some(pid);
        let member_pid = u32::from_ne_bytes(flags[2..].try_into().expect("four pid bytes"));
        if member_pid != 0 {
            *self
                .0
                .member_pid
                .lock()
                .map_err(|_| SessionChildError::IoFailed)? = Some(member_pid);
            emit_fixture_event(&format!("BoundaryMemberPid:{member_pid}"));
        }
        *self
            .0
            .command
            .lock()
            .map_err(|_| SessionChildError::IoFailed)? = Some(command_write);
        let report = fixture_report(expectation, pid);
        emit_fixture_event("PendingExecHandoffReady");
        Ok(Box::new(FixturePending {
            state: self.0.clone(),
            report,
            pidfd: Some(pidfd),
            completed: false,
        }))
    }
    fn poll_child(&self) -> Result<Option<std::process::ExitStatus>, SessionChildError> {
        let pid = self
            .0
            .pid
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?
            .ok_or(SessionChildError::IoFailed)?;
        let mut raw = 0;
        let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut raw, libc::WNOHANG) };
        if result == 0 {
            return Ok(None);
        }
        if result != pid as libc::pid_t {
            return Err(SessionChildError::IoFailed);
        }
        if self.0.reaped.swap(true, Ordering::SeqCst) {
            return Err(SessionChildError::IoFailed);
        }
        emit_fixture_event("LeaderReaped");
        Ok(Some(std::process::ExitStatus::from_raw(raw)))
    }
    fn authoritative_pidfd(&self) -> RawFd {
        self.0
            .pidfd
            .lock()
            .ok()
            .and_then(|fd| fd.as_ref().map(AsRawFd::as_raw_fd))
            .unwrap_or(-1)
    }
}
impl PendingExecHandoff for FixturePending {
    fn report(&self) -> &SessionChildReport {
        &self.report
    }
    fn authoritative_pidfd(&self) -> RawFd {
        self.pidfd.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
    fn commit_exec(mut self: Box<Self>) -> Result<SessionChildReport, SessionChildError> {
        let count = self.state.commit_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("CommitExecCalled:count={count}"));
        *self
            .state
            .pidfd
            .lock()
            .map_err(|_| SessionChildError::IoFailed)? = self.pidfd.take();
        self.completed = true;
        Ok(self.report.clone())
    }
    fn abort(mut self: Box<Self>) -> Result<(), SessionChildError> {
        let count = self.state.abort_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("ProbeAbortRequested:count={count}"));
        drop(
            self.state
                .command
                .lock()
                .map_err(|_| SessionChildError::IoFailed)?
                .take(),
        );
        let pid = self
            .state
            .pid
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?
            .ok_or(SessionChildError::IoFailed)?;
        let mut raw = 0;
        if unsafe { libc::waitpid(pid as libc::pid_t, &mut raw, 0) } != pid as libc::pid_t {
            return Err(SessionChildError::IoFailed);
        }
        if self.state.reaped.swap(true, Ordering::SeqCst) {
            return Err(SessionChildError::IoFailed);
        }
        emit_fixture_event("ProbeReaped:count=1");
        self.pidfd.take();
        self.completed = true;
        Ok(())
    }
}
impl Drop for FixturePending {
    fn drop(&mut self) {
        if !self.completed {
            if let Ok(pid) = self.state.pid.lock() {
                if let Some(pid) = *pid {
                    unsafe {
                        libc::kill(pid as libc::pid_t, libc::SIGKILL);
                        libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0);
                    }
                }
            }
        }
    }
}

struct FixtureScopeManager(Arc<FixtureState>);
impl PayloadScopeManager for FixtureScopeManager {
    fn requires_supervisor_registration(&self) -> bool {
        self.0.mode.requires_registration()
    }
    fn prepare(
        &self,
        _: &SessionChildReport,
        _: RawFd,
        expected_uid: u32,
        logind: &niralis_session::LogindSessionId,
        _: u32,
        _: u32,
        _: Instant,
    ) -> Result<Box<dyn AuthoritativePayloadScope>, PayloadScopeError> {
        emit_fixture_event("ScopePrepared");
        emit_fixture_event("PinAcquired");
        Ok(Box::new(FixtureScope {
            state: self.0.clone(),
            identity: niralis_session::PayloadScopeIdentity {
                unit_name: "niralis-payload-00000000000000000000000000000000.scope".into(),
                invocation_id: "00000000000000000000000000000000".into(),
                expected_uid,
                logind_session_id: logind.clone(),
            },
        }))
    }
}
struct FixtureScope {
    state: Arc<FixtureState>,
    identity: niralis_session::PayloadScopeIdentity,
}
