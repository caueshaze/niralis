    #[test]
    fn eligible_deadline_enters_forced_coordinator() {
        let scope = TestScope::new(Some(
            crate::payload_scope::PayloadScopeError::BoundaryNotEmpty,
        ));
        let deadline = GracefulTerminationOutcome::DeadlineExpired {
            cause: TerminationCause::WorkerSignal(WorkerTerminationSignal::Sigterm),
            leader_exit: None,
        };
        assert!(matches!(
            consume_graceful_outcome(deadline, &scope),
            GracefulFinalizationDecision::NeedsEscalation(
                EscalationEligibility::Eligible {
                    cause: TerminationCause::WorkerSignal(WorkerTerminationSignal::Sigterm),
                    leader_exit: None,
                }
            )
        ));
    }

    #[test]
    fn identity_failure_is_never_eligible_for_forced_kill() {
        let scope = TestScope::new(Some(crate::payload_scope::PayloadScopeError::UnitReplaced));
        let deadline = GracefulTerminationOutcome::DeadlineExpired {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: None,
        };
        assert!(matches!(
            consume_graceful_outcome(deadline, &scope),
            GracefulFinalizationDecision::NeedsEscalation(
                EscalationEligibility::RecoveryRequired {
                    reason: RecoveryReason::BoundaryIdentityChanged,
                    ..
                }
            )
        ));
        assert_eq!(scope.requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn worker_inside_boundary_requires_recovery_without_forced_kill() {
        let scope = TestScope::new(Some(
            crate::payload_scope::PayloadScopeError::WorkerInsideBoundary,
        ));
        let deadline = GracefulTerminationOutcome::DeadlineExpired {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: None,
        };
        assert!(matches!(
            consume_graceful_outcome(deadline, &scope),
            GracefulFinalizationDecision::NeedsEscalation(
                EscalationEligibility::RecoveryRequired {
                    reason: RecoveryReason::BoundaryIdentityUnproven,
                    ..
                }
            )
        ));
        assert_eq!(scope.requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn forced_timer_is_not_armed_when_kill_is_not_confirmed() {
        let scope = TestScope::new(None).with_forced_request_failure(
            crate::payload_scope::PayloadScopeError::BusUnavailable,
        );
        let mut coordinator = ForcedTerminationCoordinator::new(
            TerminationCause::InternalTerminateRequest,
            None,
        )
        .unwrap();
        assert!(matches!(
            coordinator.begin(Duration::from_millis(1), &scope),
            Err(ForcedTerminationOutcome::InfrastructureFailure { .. })
        ));
        assert!(!coordinator.consume_deadline().unwrap());
        assert_eq!(scope.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn forced_timer_is_not_armed_when_post_kill_validation_fails() {
        let scope = TestScope::new(None).with_forced_post_kill_failure(
            crate::payload_scope::PayloadScopeError::BusUnavailable,
        );
        let mut coordinator = ForcedTerminationCoordinator::new(
            TerminationCause::InternalTerminateRequest,
            None,
        )
        .unwrap();
        assert!(matches!(
            coordinator.begin(Duration::from_millis(1), &scope),
            Err(ForcedTerminationOutcome::InfrastructureFailure {
                stage: ForcedTerminationStage::PostKillValidation,
                ..
            })
        ));
        assert!(!coordinator.consume_deadline().unwrap());
        assert_eq!(scope.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn forced_kill_attempt_cannot_be_repeated() {
        let scope = TestScope::new(None);
        let mut coordinator = ForcedTerminationCoordinator::new(
            TerminationCause::InternalTerminateRequest,
            None,
        )
        .unwrap();
        let _observer = coordinator
            .begin(Duration::from_secs(1), &scope)
            .unwrap();
        assert!(coordinator
            .begin(Duration::from_secs(1), &scope)
            .is_err());
        assert_eq!(scope.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn forced_deadline_preserves_first_leader_exit() {
        let mut coordinator = ForcedTerminationCoordinator::new(
            TerminationCause::InternalTerminateRequest,
            Some(LeaderExit::ExitedNonZero(9)),
        )
        .unwrap();
        coordinator.record_leader_exit(LeaderExit::KilledBySignal(libc::SIGKILL));
        assert_eq!(
            coordinator.deadline_expired(),
            ForcedTerminationOutcome::ForcedDeadlineExpired {
                cause: TerminationCause::InternalTerminateRequest,
                leader_exit: Some(LeaderExit::ExitedNonZero(9)),
            }
        );
    }
