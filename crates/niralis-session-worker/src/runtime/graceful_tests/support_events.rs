    impl EventScope {
        fn new(
            pid_fd: RawFd,
            cooperative: bool,
            fail: Option<crate::payload_scope::PayloadScopeError>,
        ) -> Self {
            Self {
                identity: niralis_session::PayloadScopeIdentity {
                    unit_name: "niralis-payload-11111111111111111111111111111111.scope".into(),
                    invocation_id: "11111111111111111111111111111111".into(),
                    expected_uid: 1000,
                    logind_session_id: niralis_session::LogindSessionId::new("1".into()).unwrap(),
                },
                boundary_fd: event_fd(),
                pid_fd,
                cooperative,
                terminal: AtomicBool::new(false),
                requests: AtomicUsize::new(0),
                unrefs: AtomicUsize::new(0),
                fail,
                observe_fail: None,
            }
        }
    }
    impl crate::payload_scope::AuthoritativePayloadScope for EventScope {
        fn identity(&self) -> &niralis_session::PayloadScopeIdentity {
            &self.identity
        }
        fn control_group(&self) -> &str {
            "/test"
        }
        fn cleanup(
            self: Box<Self>,
            _: Instant,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            Ok(())
        }
        fn create_boundary_observer(
            &self,
        ) -> Result<
            Box<dyn crate::payload_scope::PayloadBoundaryObserver>,
            crate::payload_scope::PayloadScopeError,
        > {
            let fd = unsafe { libc::fcntl(self.boundary_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                Err(crate::payload_scope::PayloadScopeError::ObserverFailed)
            } else {
                Ok(Box::new(EventObserver(unsafe { OwnedFd::from_raw_fd(fd) })))
            }
        }
        fn request_graceful_termination(
            &self,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            self.requests.fetch_add(1, AtomicOrdering::SeqCst);
            if let Some(error) = &self.fail {
                return Err(error.clone());
            }
            if self.cooperative {
                self.terminal.store(true, AtomicOrdering::SeqCst);
                write_event(self.pid_fd);
                write_event(self.boundary_fd.as_raw_fd());
            }
            Ok(())
        }
        fn validate_forced_termination_eligibility(
            &self,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            match &self.fail {
                Some(crate::payload_scope::PayloadScopeError::BoundaryNotEmpty
                | crate::payload_scope::PayloadScopeError::UnitNotTerminal) => Ok(()),
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }
        fn request_forced_termination(
            &self,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            self.requests.fetch_add(1, AtomicOrdering::SeqCst);
            if let Some(error) = &self.fail {
                if !matches!(
                    error,
                    crate::payload_scope::PayloadScopeError::BoundaryNotEmpty
                        | crate::payload_scope::PayloadScopeError::UnitNotTerminal
                ) {
                    return Err(error.clone());
                }
            }
            if self.cooperative {
                self.terminal.store(true, AtomicOrdering::SeqCst);
                write_event(self.pid_fd);
                write_event(self.boundary_fd.as_raw_fd());
            }
            Ok(())
        }
        fn validate_forced_termination_post_kill(
            &self,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            Ok(())
        }
        fn boundary_appears_terminal(
            &self,
        ) -> Result<bool, crate::payload_scope::PayloadScopeError> {
            if let Some(error) = &self.observe_fail {
                Err(error.clone())
            } else {
                Ok(self.terminal.load(AtomicOrdering::SeqCst))
            }
        }
        fn prove_empty_boundary(
            &self,
            leader_exit: &crate::termination::LeaderExit,
        ) -> Result<crate::termination::BoundaryEmptyProof, crate::payload_scope::PayloadScopeError>
        {
            if !self.terminal.load(AtomicOrdering::SeqCst) {
                return Err(crate::payload_scope::PayloadScopeError::BoundaryNotEmpty);
            }
            Ok(crate::termination::BoundaryEmptyProof::new(
                &self.identity,
                self.control_group(),
                leader_exit.clone(),
            ))
        }
        fn release_pin(&mut self) -> Result<(), crate::payload_scope::PayloadScopeError> {
            self.unrefs.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(())
        }
    }

    struct EventRunner {
        pidfd: OwnedFd,
        status: Mutex<Option<std::process::ExitStatus>>,
    }
    impl crate::session_child::SessionChildRunner for EventRunner {
        fn run_child_until_ready(
            &self,
            _: crate::session_child::SessionChildExpectation,
        ) -> Result<
            Box<dyn crate::session_child::PendingExecHandoff>,
            crate::session_child::SessionChildError,
        > {
            Err(crate::session_child::SessionChildError::IoFailed)
        }
        fn authoritative_pidfd(&self) -> RawFd {
            self.pidfd.as_raw_fd()
        }
        fn poll_child(
            &self,
        ) -> Result<Option<std::process::ExitStatus>, crate::session_child::SessionChildError>
        {
            let _ = read_event(self.pidfd.as_raw_fd());
            Ok(self.status.lock().unwrap().take())
        }
    }

    struct OwnedLifecycle(Arc<AtomicUsize>);
    impl Drop for OwnedLifecycle {
        fn drop(&mut self) {
            self.0.fetch_add(1, AtomicOrdering::SeqCst);
        }
    }

    fn event_fd() -> OwnedFd {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    }
    fn write_event(fd: RawFd) {
        let one = 1_u64;
        assert_eq!(
            unsafe { libc::write(fd, (&one as *const u64).cast(), 8) },
            8
        );
    }
    fn read_event(fd: RawFd) -> bool {
        let mut value = 0_u64;
        (unsafe { libc::read(fd, (&mut value as *mut u64).cast(), 8) }) == 8
    }

    fn run_signal_case(signal: i32, expected: crate::termination::WorkerTerminationSignal) {
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        set_supervisor_channel_fd(-1);
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(0))),
        };
        let scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        let drops = Arc::new(AtomicUsize::new(0));
        let pam = OwnedLifecycle(drops.clone());
        let vt = OwnedLifecycle(drops.clone());
        assert_eq!(
            unsafe { libc::pthread_kill(libc::pthread_self(), signal) },
            0
        );
        let result = wait_for_session_with_grace(
            None,
            &runner,
            "worker".into(),
            1,
            1,
            &scope,
            Duration::from_millis(100),
            unsafe { libc::getuid() },
        )
        .unwrap();
        assert!(
            matches!(result, SessionWaitResult::Graceful(crate::termination::GracefulTerminationOutcome::BoundaryTerminalCandidate { cause: crate::termination::TerminationCause::WorkerSignal(value), leader_exit: Some(crate::termination::LeaderExit::ExitedZero), .. }) if value == expected)
        );
        assert_eq!(scope.requests.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(drops.load(AtomicOrdering::SeqCst), 0);
        drop((pam, vt));
        set_worker_signal_fd(-1);
    }
