    #[test]
    fn forced_observer_and_timer_ready_prefers_reap_and_empty_proof() {
        let _lock = lock_signal_tests();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        set_supervisor_channel_fd(-1);
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(libc::SIGKILL))),
        };
        let scope = EventScope::new(runner.pidfd.as_raw_fd(), true, None);
        let outcome = wait_for_forced_cleanup(
            ForcedWaitContext {
                listener: None,
                child_runner: &runner,
                worker_id: "worker",
                session_pid: 1,
                session_pgid: 1,
                authoritative_scope: &scope,
                expected_control_uid: unsafe { libc::getuid() },
            },
            crate::termination::TerminationCause::InternalTerminateRequest,
            None,
            Duration::from_nanos(1),
        );
        assert!(matches!(
            outcome,
            crate::termination::ForcedTerminationOutcome::BoundaryEmpty {
                leader_exit: crate::termination::LeaderExit::KilledBySignal(libc::SIGKILL),
                ..
            }
        ));
        assert_eq!(scope.requests.load(AtomicOrdering::SeqCst), 1);
        set_worker_signal_fd(-1);
    }

    #[test]
    fn forced_leader_and_timer_ready_preserves_exit_without_false_proof() {
        let _lock = lock_signal_tests();
        let signals = crate::termination::WorkerSignalFd::install().unwrap();
        set_worker_signal_fd(signals.as_raw_fd());
        set_supervisor_channel_fd(-1);
        let runner = EventRunner {
            pidfd: event_fd(),
            status: Mutex::new(Some(std::process::ExitStatus::from_raw(libc::SIGKILL))),
        };
        write_event(runner.pidfd.as_raw_fd());
        let scope = EventScope::new(runner.pidfd.as_raw_fd(), false, None);
        let outcome = wait_for_forced_cleanup(
            ForcedWaitContext {
                listener: None,
                child_runner: &runner,
                worker_id: "worker",
                session_pid: 1,
                session_pgid: 1,
                authoritative_scope: &scope,
                expected_control_uid: unsafe { libc::getuid() },
            },
            crate::termination::TerminationCause::InternalTerminateRequest,
            None,
            Duration::from_nanos(1),
        );
        assert_eq!(
            outcome,
            crate::termination::ForcedTerminationOutcome::ForcedDeadlineExpired {
                cause: crate::termination::TerminationCause::InternalTerminateRequest,
                leader_exit: Some(crate::termination::LeaderExit::KilledBySignal(libc::SIGKILL)),
            }
        );
        set_worker_signal_fd(-1);
    }

    #[test]
    fn forced_unit_disappearance_uses_the_existing_strong_empty_proof() {
        let mut scope = EventScope::new(-1, false, None);
        scope.terminal.store(true, AtomicOrdering::SeqCst);
        scope.observe_fail = Some(crate::payload_scope::PayloadScopeError::InvocationUnavailable);
        let mut coordinator = crate::termination::ForcedTerminationCoordinator::new(
            crate::termination::TerminationCause::InternalTerminateRequest,
            Some(crate::termination::LeaderExit::KilledBySignal(libc::SIGKILL)),
        )
        .unwrap();
        assert!(matches!(
            try_forced_empty_proof(&scope, &mut coordinator),
            Some(crate::termination::ForcedTerminationOutcome::BoundaryEmpty { .. })
        ));
    }

    #[test]
    fn forced_finalizer_reuses_unref_pam_vt_ordering() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let identity = niralis_session::PayloadScopeIdentity {
            unit_name: "niralis-payload-00000000000000000000000000000000.scope".into(),
            invocation_id: "00000000000000000000000000000000".into(),
            expected_uid: 1000,
            logind_session_id: niralis_session::LogindSessionId::new("1".into()).unwrap(),
        };
        let proof = crate::termination::BoundaryEmptyProof::new(
            &identity,
            "/test",
            crate::termination::LeaderExit::KilledBySignal(libc::SIGKILL),
        );
        let mut scope = OrderedScope {
            identity,
            events: events.clone(),
            unref_fails: false,
        };
        let transaction: Box<dyn niralis_auth::AuthenticatedTransaction> =
            Box::new(OrderedTransaction {
                events: events.clone(),
                close_fails: false,
            });
        let mut terminal = VirtualTerminalGuard::new(Box::new(OrderedLease {
            events: events.clone(),
            fail: false,
        }));
        assert!(finalize_session_after_empty_proof(
            &mut scope,
            transaction,
            &mut terminal,
            proof,
            true,
        )
        .is_ok());
        assert_eq!(
            *events.lock().unwrap(),
            [
                "unit_unref_attempted",
                "pam_close_started",
                "pam_close_completed",
                "pam_dropped",
                "vt_released"
            ]
        );
    }
