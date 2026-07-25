    #[test]
    fn bus_loss_after_kill_does_not_produce_candidate() {
        let mut steps = kill_steps(ScriptedInvocationResponse::Success);
        steps.push(ScriptedInvocationStep::new(
            InvocationOperation::ReadPropertiesAfterKill,
            ScriptedInvocationResponse::BusDisconnected,
        ));
        let backend = ScriptedInvocationBackend::new(steps);
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::BusUnavailable
        );
        backend.assert_consumed();
    }

    #[test]
    fn post_kill_terminal_scope_with_cleared_control_group_is_not_replacement() {
        let mut steps = kill_steps(ScriptedInvocationResponse::Success);
        steps.push(ScriptedInvocationStep::new(
            InvocationOperation::ReadPropertiesAfterKill,
            ScriptedInvocationResponse::Properties(
                terminal_properties_with_cleared_control_group(),
            ),
        ));
        let backend = ScriptedInvocationBackend::new(steps);
        async_io::block_on(request_graceful_termination_invocation(
            &backend,
            &identity_a(),
            &pinned_a(),
            CONTROL_GROUP,
        ))
        .unwrap();
        backend.assert_consumed();
    }

    #[test]
    fn forced_sigkill_is_invocation_bound_and_sent_once() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterRef,
                ScriptedInvocationResponse::Properties(properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::KillPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterKill,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
        ]);
        async_io::block_on(request_forced_termination_invocation(
            &backend,
            &identity_a(),
            &pinned_a(),
            CONTROL_GROUP,
        ))
        .unwrap();
        backend.assert_signals(&[libc::SIGKILL]);
        backend.assert_consumed();
    }

    #[test]
    fn forced_pre_kill_identity_divergence_sends_no_signal() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::Resolved(path_b()),
        )]);
        assert_eq!(
            async_io::block_on(request_forced_termination_invocation(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            )),
            Err(PayloadScopeError::UnitReplaced)
        );
        backend.assert_signals(&[]);
        backend.assert_consumed();
    }

    #[test]
    fn forced_bus_or_owner_loss_before_kill_sends_no_signal() {
        for response in [
            ScriptedInvocationResponse::BusDisconnected,
            ScriptedInvocationResponse::ServiceOwnerChanged,
        ] {
            let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                response,
            )]);
            let error = async_io::block_on(request_forced_termination_invocation(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err();
            assert!(matches!(
                error,
                PayloadScopeError::BusUnavailable | PayloadScopeError::ServiceOwnerChanged
            ));
            backend.assert_signals(&[]);
            backend.assert_consumed();
        }
    }

    #[test]
    fn forced_kill_failure_is_not_retried_or_treated_as_success() {
        let backend = ScriptedInvocationBackend::new(kill_steps(
            ScriptedInvocationResponse::BusDisconnected,
        ));
        assert_eq!(
            async_io::block_on(request_forced_termination_invocation(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            )),
            Err(PayloadScopeError::BusUnavailable)
        );
        backend.assert_signals(&[libc::SIGKILL]);
        backend.assert_consumed();
    }

