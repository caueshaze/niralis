    #[test]
    fn terminal_pinned_scope_with_cleared_control_group_and_absent_cgroup_proves_empty() {
        let terminal = terminal_properties_with_cleared_control_group();
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterObserver,
                ScriptedInvocationResponse::Properties(terminal.clone()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal.clone()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryState(CgroupEmptyState::Absent),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::UnrefPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
        ]);
        let identity = identity_a();
        let mut pinned = pinned_a();
        assert!(async_io::block_on(boundary_appears_terminal(
            &backend,
            &identity,
            &pinned,
            CONTROL_GROUP,
        ))
        .unwrap());
        async_io::block_on(prove_empty_boundary(
            &backend,
            &identity,
            &pinned,
            CONTROL_GROUP,
            u32::MAX,
            u32::MAX,
            &crate::termination::LeaderExit::ExitedZero,
        ))
        .unwrap();
        async_io::block_on(release_pin(&backend, &identity, &mut pinned)).unwrap();
        assert!(!pinned.reference_held);
        backend.assert_consumed();
    }

    #[test]
    fn observer_zero_then_populated_one_prevents_proof() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryNotEmpty,
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
            PayloadScopeError::BoundaryNotEmpty
        );
        backend.assert_consumed();
    }

    #[test]
    fn no_such_unit_empty_proof_requires_two_missing_resolutions_and_absent_cgroup() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::NoSuchUnit,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryState(CgroupEmptyState::Absent),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::NoSuchUnit,
            ),
        ]);
        async_io::block_on(prove_empty_boundary(
            &backend,
            &identity_a(),
            &pinned_a(),
            CONTROL_GROUP,
            u32::MAX,
            u32::MAX,
            &crate::termination::LeaderExit::ExitedZero,
        ))
        .unwrap();
        backend.assert_consumed();
    }

    #[test]
    fn no_such_unit_with_populated_boundary_never_proves_empty() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::NoSuchUnit,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryNotEmpty,
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
            PayloadScopeError::BoundaryNotEmpty
        );
        backend.assert_consumed();
    }

    #[test]
    fn unref_is_never_called_before_empty_proof() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryNotEmpty,
            ),
        ]);
        let result = async_io::block_on(prove_empty_boundary(
            &backend,
            &identity_a(),
            &pinned_a(),
            CONTROL_GROUP,
            u32::MAX,
            u32::MAX,
            &crate::termination::LeaderExit::ExitedZero,
        ));
        assert_eq!(result.unwrap_err(), PayloadScopeError::BoundaryNotEmpty);
        backend.assert_consumed();
    }

