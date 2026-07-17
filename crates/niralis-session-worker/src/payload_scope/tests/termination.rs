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
    fn cleared_control_group_before_terminal_state_is_identity_change() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterObserver,
                ScriptedInvocationResponse::Properties(InvocationUnitProperties {
                    control_group: String::new(),
                    ..properties_a()
                }),
            ),
        ]);
        assert_eq!(
            async_io::block_on(boundary_appears_terminal(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            )),
            Err(PayloadScopeError::UnitReplaced)
        );
        backend.assert_consumed();
    }

    #[test]
    fn observer_wakeup_during_bus_loss_does_not_produce_candidate() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::CreateBoundaryObserver,
                ScriptedInvocationResponse::Success,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::BusDisconnected,
            ),
        ]);
        let mut observer = backend
            .create_boundary_observer(INVOCATION_A, &path_a(), CONTROL_GROUP)
            .unwrap();
        observer.consume_wakeup().unwrap();
        assert_eq!(
            async_io::block_on(boundary_appears_terminal(
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
    fn replacement_during_empty_proof_prevents_finalization() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::Resolved(path_b()),
        )]);
        assert_eq!(
            async_io::block_on(prove_empty_boundary(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
                u32::MAX,
                u32::MAX,
                &crate::termination::LeaderExit::ExitedZero,
            ))
            .unwrap_err(),
            PayloadScopeError::UnitReplaced
        );
        backend.assert_consumed();
    }

    #[test]
    fn replacement_between_empty_proof_revalidations_is_detected() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(
                    terminal_properties_with_cleared_control_group(),
                ),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryState(CgroupEmptyState::Absent),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_b()),
            ),
        ]);
        assert_eq!(
            async_io::block_on(prove_empty_boundary(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
                u32::MAX,
                u32::MAX,
                &crate::termination::LeaderExit::ExitedZero,
            ))
            .unwrap_err(),
            PayloadScopeError::UnitReplaced
        );
        backend.assert_consumed();
    }

