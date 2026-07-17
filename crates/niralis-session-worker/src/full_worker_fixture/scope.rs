impl AuthoritativePayloadScope for FixtureScope {
    fn identity(&self) -> &niralis_session::PayloadScopeIdentity {
        &self.identity
    }
    fn control_group(&self) -> &str {
        "/fixture.scope"
    }
    fn cleanup(self: Box<Self>, _: Instant) -> Result<(), PayloadScopeError> {
        let count = self.state.cleanup_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("ScopeCleanupRequested:count={count}"));
        let unref = self.state.unref_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("UnitUnrefAttempted:count={unref}"));
        Ok(())
    }
    fn cleanup_preserving_pin(&mut self, _: Instant) -> Result<(), PayloadScopeError> {
        let count = self.state.cleanup_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("ScopeCleanupRequested:count={count}"));
        if self.state.mode == FixtureMode::BarrierCDisappearance {
            emit_fixture_event("OriginalCgroupAbsent");
            emit_fixture_event("CleanupResolveByInvocation:count=1");
            emit_fixture_event("CleanupPropertiesValidated:count=1");
            emit_fixture_event("CleanupResolveByInvocation:count=2");
            emit_fixture_event("CleanupPropertiesValidated:count=2");
            emit_fixture_event("PreCommitDisappearanceProofEstablished");
        }
        emit_fixture_event("PinHeldAfterScopeCleanup");
        Ok(())
    }
    fn create_boundary_observer(
        &self,
    ) -> Result<Box<dyn PayloadBoundaryObserver>, PayloadScopeError> {
        let fd = unsafe { libc::fcntl(self.state.boundary.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            Err(PayloadScopeError::ObserverFailed)
        } else {
            Ok(Box::new(FixtureObserver(unsafe {
                OwnedFd::from_raw_fd(fd)
            })))
        }
    }
    fn request_graceful_termination(&self) -> Result<(), PayloadScopeError> {
        let count = self.state.kill_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("GracefulRequestObserved:count={count}"));
        match self.state.mode {
            FixtureMode::InvalidationBeforeKill => {
                emit_fixture_event("InvocationInvalidatedBeforeKill");
                return Err(PayloadScopeError::InvocationUnavailable);
            }
            FixtureMode::BusLossBeforeKill => {
                emit_fixture_event("SystemBusLostBeforeKill");
                return Err(PayloadScopeError::BusUnavailable);
            }
            _ => {}
        }
        if matches!(
            self.state.mode,
            FixtureMode::Cooperative
                | FixtureMode::ReplacementDuringProof
                | FixtureMode::LauncherChannel
        ) {
            let state = self.state.clone();
            std::thread::spawn(move || {
                let launcher_driven = state.mode == FixtureMode::LauncherChannel;
                if !launcher_driven && !read_fixture_command("AllowPayloadExit") {
                    return;
                }
                let command = state.command.lock().ok().and_then(|mut value| value.take());
                let Some(command) = command else {
                    return;
                };
                if unsafe { libc::write(command.as_raw_fd(), b"x".as_ptr().cast(), 1) } != 1 {
                    return;
                }
                let fd = state.pidfd.lock().ok().and_then(|fd| {
                    fd.as_ref().and_then(|fd| unsafe {
                        let value = libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3);
                        (value >= 0).then(|| OwnedFd::from_raw_fd(value))
                    })
                });
                if let Some(fd) = fd {
                    let mut poll = libc::pollfd {
                        fd: fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe {
                        libc::poll(&mut poll, 1, -1);
                    }
                    if !launcher_driven && !read_fixture_command("MakeBoundaryTerminal") {
                        return;
                    }
                    state.terminal.store(true, Ordering::SeqCst);
                    let one = 1_u64;
                    unsafe {
                        libc::write(state.boundary.as_raw_fd(), (&one as *const u64).cast(), 8);
                    }
                }
            });
        }
        Ok(())
    }
    fn validate_forced_termination_eligibility(&self) -> Result<(), PayloadScopeError> {
        if self.state.mode == FixtureMode::ReplacementBeforeForcedKill {
            emit_fixture_event("InvocationReplacedBeforeForcedKill");
            return Err(PayloadScopeError::UnitReplaced);
        }
        Ok(())
    }
    fn request_forced_termination(&self) -> Result<(), PayloadScopeError> {
        let count = self
            .state
            .forced_kill_count
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        emit_fixture_event(&format!("ForcedKillObserved:count={count}"));
        if self.state.mode == FixtureMode::ForcedDeadline {
            return Ok(());
        }
        let target = if self.state.mode == FixtureMode::LeaderExitRemainingMember {
            self.state.member_pid.lock().ok().and_then(|pid| *pid)
        } else {
            self.state.pid.lock().ok().and_then(|pid| *pid)
        }
        .ok_or(PayloadScopeError::InvalidMembership)?;
        let pidfd = open_pidfd(target).map_err(|_| PayloadScopeError::InvalidMembership)?;
        if unsafe { libc::kill(target as libc::pid_t, libc::SIGKILL) } != 0 {
            return Err(PayloadScopeError::TransportFailure);
        }
        let state = self.state.clone();
        std::thread::spawn(move || {
            let mut pollfd = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pollfd, 1, -1) } != 1 {
                return;
            }
            state.terminal.store(true, Ordering::SeqCst);
            let one = 1_u64;
            unsafe {
                libc::write(state.boundary.as_raw_fd(), (&one as *const u64).cast(), 8);
            }
        });
        Ok(())
    }
    fn validate_forced_termination_post_kill(&self) -> Result<(), PayloadScopeError> {
        Ok(())
    }
    fn boundary_appears_terminal(&self) -> Result<bool, PayloadScopeError> {
        if self.state.mode == FixtureMode::BusLossAfterForcedKill
            && self.state.forced_kill_count.load(Ordering::SeqCst) > 0
        {
            emit_fixture_event("SystemBusLostAfterForcedKill");
            return Err(PayloadScopeError::BusUnavailable);
        }
        Ok(self.state.terminal.load(Ordering::SeqCst))
    }
    fn prove_empty_boundary(
        &self,
        exit: &LeaderExit,
    ) -> Result<BoundaryEmptyProof, PayloadScopeError> {
        if !self.state.terminal.load(Ordering::SeqCst) || !self.state.reaped.load(Ordering::SeqCst)
        {
            return Err(PayloadScopeError::BoundaryNotEmpty);
        }
        if self.state.mode == FixtureMode::ReplacementDuringProof {
            emit_fixture_event("InvocationReplacedDuringProof");
            return Err(PayloadScopeError::UnitReplaced);
        }
        let count = self.state.proof_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("BoundaryEmptyProofEstablished:count={count}"));
        Ok(BoundaryEmptyProof::new(
            &self.identity,
            self.control_group(),
            exit.clone(),
        ))
    }
    fn release_pin(&mut self) -> Result<(), PayloadScopeError> {
        let count = self.state.unref_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("UnitUnrefAttempted:count={count}"));
        Ok(())
    }
}
struct FixtureObserver(OwnedFd);
impl PayloadBoundaryObserver for FixtureObserver {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
    fn poll_events(&self) -> libc::c_short {
        libc::POLLIN
    }
    fn consume_wakeup(&mut self) -> Result<(), PayloadScopeError> {
        let mut value = 0_u64;
        (unsafe { libc::read(self.0.as_raw_fd(), (&mut value as *mut u64).cast(), 8) } == 8)
            .then_some(())
            .ok_or(PayloadScopeError::ObserverFailed)
    }
}

fn pipe() -> Result<(OwnedFd, OwnedFd), SessionChildError> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SessionChildError::IoFailed);
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}
fn open_pidfd(pid: u32) -> Result<OwnedFd, SessionChildError> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as RawFd;
    if fd < 0 {
        Err(SessionChildError::IoFailed)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn signal_has_default_disposition(signal: libc::c_int) -> bool {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    (unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) == 0 })
        && action.sa_sigaction == libc::SIG_DFL
}
