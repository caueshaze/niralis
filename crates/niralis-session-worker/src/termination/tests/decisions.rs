    #[test]
    fn only_candidate_with_reaped_leader_and_empty_proof_can_finalize() {
        let scope = TestScope::new(None);
        let candidate = GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: Some(LeaderExit::ExitedZero),
            observation: BoundaryTerminalObservation::CgroupEventRevalidated,
        };
        assert!(matches!(
            consume_graceful_outcome(candidate, &scope),
            GracefulFinalizationDecision::FinalizeCooperative(proof)
                if proof.leader_exit() == &LeaderExit::ExitedZero
        ));

        let without_reap = GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: None,
            observation: BoundaryTerminalObservation::CgroupEventRevalidated,
        };
        assert!(matches!(
            consume_graceful_outcome(without_reap, &scope),
            GracefulFinalizationDecision::NeedsEscalation(
                EscalationEligibility::Eligible { leader_exit: None, .. }
            )
        ));
    }
    #[test]
    fn failed_proof_and_non_candidate_outcomes_retain_nonfinal_state() {
        let populated = TestScope::new(Some(
            crate::payload_scope::PayloadScopeError::BoundaryNotEmpty,
        ));
        let candidate = GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: Some(LeaderExit::ExitedZero),
            observation: BoundaryTerminalObservation::CgroupEventRevalidated,
        };
        assert!(matches!(
            consume_graceful_outcome(candidate, &populated),
            GracefulFinalizationDecision::NeedsEscalation(
                EscalationEligibility::Eligible { .. }
            )
        ));

        let replaced = TestScope::new(Some(crate::payload_scope::PayloadScopeError::UnitReplaced));
        let candidate = GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: Some(LeaderExit::ExitedZero),
            observation: BoundaryTerminalObservation::CgroupEventRevalidated,
        };
        assert!(matches!(
            consume_graceful_outcome(candidate, &replaced),
            GracefulFinalizationDecision::RecoveryRequired { .. }
        ));

        let deadline = GracefulTerminationOutcome::DeadlineExpired {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: Some(LeaderExit::ExitedZero),
        };
        assert!(matches!(
            consume_graceful_outcome(deadline, &populated),
            GracefulFinalizationDecision::NeedsEscalation(
                EscalationEligibility::Eligible { .. }
            )
        ));
    }
    #[test]
    fn unit_replacement_is_recovery_required() {
        let scope = TestScope::new(Some(crate::payload_scope::PayloadScopeError::UnitReplaced));
        let mut coordinator = GracefulTerminationCoordinator::new().unwrap();
        assert!(matches!(
            coordinator.begin(
                TerminationCause::InternalTerminateRequest,
                Duration::from_secs(1),
                &scope
            ),
            Err(GracefulTerminationOutcome::RecoveryRequired {
                reason: RecoveryReason::BoundaryIdentityChanged,
                ..
            })
        ));
        assert_eq!(scope.requests.load(Ordering::SeqCst), 1);
    }
