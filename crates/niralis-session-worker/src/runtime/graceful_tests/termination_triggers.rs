    #[test]
    fn production_loop_cooperates_for_real_worker_signals() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        run_signal_case(
            libc::SIGTERM,
            crate::termination::WorkerTerminationSignal::Sigterm,
        );
        run_signal_case(
            libc::SIGINT,
            crate::termination::WorkerTerminationSignal::Sigint,
        );
        run_signal_case(
            libc::SIGHUP,
            crate::termination::WorkerTerminationSignal::Sighup,
        );
    }

    #[test]
    fn production_loop_deadline_and_infrastructure_retain_ownership() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        for failure in [
            None,
            Some(crate::payload_scope::PayloadScopeError::BusUnavailable),
        ] {
            let runner = EventRunner {
                pidfd: event_fd(),
                status: Mutex::new(None),
            };
            let scope = EventScope::new(runner.pidfd.as_raw_fd(), false, failure.clone());
            let drops = Arc::new(AtomicUsize::new(0));
            let pam = OwnedLifecycle(drops.clone());
            let vt = OwnedLifecycle(drops.clone());
            assert_eq!(
                unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) },
                0
            );
            let result = wait_for_session_with_grace(
                None,
                &runner,
                "worker".into(),
                1,
                1,
                &scope,
                Duration::from_millis(1),
                unsafe { libc::getuid() },
            )
            .unwrap();
            if failure.is_some() {
                assert!(matches!(
                    result,
                    SessionWaitResult::Graceful(
                        crate::termination::GracefulTerminationOutcome::InfrastructureFailure { .. }
                    )
                ));
            } else {
                assert!(matches!(
                    result,
                    SessionWaitResult::Graceful(
                        crate::termination::GracefulTerminationOutcome::DeadlineExpired { .. }
                    )
                ));
            }
            assert_eq!(drops.load(AtomicOrdering::SeqCst), 0);
            drop((pam, vt));
        }
        set_worker_signal_fd(-1);
    }

    #[test]
    fn simultaneous_boundary_and_deadline_prefers_revalidated_candidate() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(42 << 8))),
        };
        let scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
        let result = wait_for_session_with_grace(
            None,
            &runner,
            "worker".into(),
            1,
            1,
            &scope,
            Duration::from_nanos(1),
            unsafe { libc::getuid() },
        )
        .unwrap();
        assert!(matches!(
            result,
            SessionWaitResult::Graceful(
                crate::termination::GracefulTerminationOutcome::BoundaryTerminalCandidate {
                    leader_exit: Some(crate::termination::LeaderExit::ExitedNonZero(42)),
                    ..
                }
            )
        ));
        set_worker_signal_fd(-1);
    }

    #[test]
    fn replacement_during_observation_is_recovery_required() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(libc::SIGSEGV))),
        };
        let mut scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        scope.observe_fail = Some(crate::payload_scope::PayloadScopeError::UnitReplaced);
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
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
            matches!(result, SessionWaitResult::Graceful(crate::termination::GracefulTerminationOutcome::RecoveryRequired { leader_exit: Some(crate::termination::LeaderExit::KilledBySignal(value)), .. }) if value == libc::SIGSEGV)
        );
        set_worker_signal_fd(-1);
    }

    #[test]
    fn simultaneous_supervisor_disconnect_and_signal_is_single_lifecycle() {
        let _lock = SIGNAL_TEST_LOCK.lock().unwrap();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        let supervisor = event_fd();
        write_event(supervisor.as_raw_fd());
        set_supervisor_channel_fd(supervisor.as_raw_fd());
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(0))),
        };
        let scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
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
        assert!(matches!(
            result,
            SessionWaitResult::Graceful(
                crate::termination::GracefulTerminationOutcome::BoundaryTerminalCandidate {
                    cause: crate::termination::TerminationCause::WorkerSignal(
                        crate::termination::WorkerTerminationSignal::Sigterm
                    ),
                    ..
                }
            )
        ));
        assert_eq!(scope.requests.load(AtomicOrdering::SeqCst), 1);
        set_supervisor_channel_fd(-1);
        set_worker_signal_fd(-1);
    }

