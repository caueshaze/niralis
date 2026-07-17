    #[test]
    fn unref_failure_does_not_keep_pam_or_vt_and_vt_failure_is_reported() {
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
            crate::termination::LeaderExit::ExitedZero,
        );
        let mut scope = OrderedScope {
            identity,
            events: events.clone(),
            unref_fails: true,
        };
        let transaction: Box<dyn niralis_auth::AuthenticatedTransaction> =
            Box::new(OrderedTransaction {
                events: events.clone(),
                close_fails: false,
            });
        let mut terminal = VirtualTerminalGuard::new(Box::new(OrderedLease {
            events: events.clone(),
            fail: true,
        }));
        assert!(
            finalize_cooperative_session(&mut scope, transaction, &mut terminal, proof).is_err()
        );
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

    #[test]
    fn pam_close_failure_still_releases_vt_and_returns_failure() {
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
            crate::termination::LeaderExit::ExitedZero,
        );
        let mut scope = OrderedScope {
            identity,
            events: events.clone(),
            unref_fails: false,
        };
        let transaction: Box<dyn niralis_auth::AuthenticatedTransaction> =
            Box::new(OrderedTransaction {
                events: events.clone(),
                close_fails: true,
            });
        let mut terminal = VirtualTerminalGuard::new(Box::new(OrderedLease {
            events: events.clone(),
            fail: false,
        }));
        assert!(
            finalize_cooperative_session(&mut scope, transaction, &mut terminal, proof).is_err()
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "unit_unref_attempted",
                "pam_close_started",
                "pam_dropped",
                "vt_released"
            ]
        );
    }
