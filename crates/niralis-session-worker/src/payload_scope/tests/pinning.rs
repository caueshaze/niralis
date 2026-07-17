    #[test]
    fn post_ref_object_path_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            object_path: path_b(),
            ..properties_a()
        });
    }

    #[test]
    fn pinned_path_invalidated_before_kill_fails_closed() {
        for response in [
            ScriptedInvocationResponse::UnknownObject,
            ScriptedInvocationResponse::NoSuchUnit,
        ] {
            let backend = ScriptedInvocationBackend::new(kill_steps(response));
            assert_eq!(
                async_io::block_on(request_graceful_termination_invocation(
                    &backend,
                    &identity_a(),
                    &pinned_a(),
                    CONTROL_GROUP,
                ))
                .unwrap_err(),
                PayloadScopeError::InvocationUnavailable
            );
            backend.assert_consumed();
        }
    }

    #[test]
    fn bus_loss_before_kill_preserves_pinned_identity() {
        let backend =
            ScriptedInvocationBackend::new(kill_steps(ScriptedInvocationResponse::BusDisconnected));
        let pinned = pinned_a();
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &backend,
                &identity_a(),
                &pinned,
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::BusUnavailable
        );
        assert!(pinned.reference_held);
        assert_eq!(pinned.object_path, path_a());
        backend.assert_consumed();
    }

    #[test]
    fn pinned_unit_never_reinterprets_reused_name() {
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
                InvocationOperation::ReadPropertiesAfterKill,
                ScriptedInvocationResponse::Properties(properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::CreateBoundaryObserver,
                ScriptedInvocationResponse::Success,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterObserver,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
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
                ScriptedInvocationResponse::BoundaryState(CgroupEmptyState::PresentEmpty),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::UnrefPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
        ]);
        let identity = identity_a();
        let mut pinned = pinned_a();
        async_io::block_on(request_graceful_termination_invocation(
            &backend,
            &identity,
            &pinned,
            CONTROL_GROUP,
        ))
        .unwrap();
        let mut observer = backend
            .create_boundary_observer(INVOCATION_A, &path_a(), CONTROL_GROUP)
            .unwrap();
        observer.consume_wakeup().unwrap();
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
    fn replacement_after_kill_does_not_receive_second_operation() {
        let mut steps = kill_steps(ScriptedInvocationResponse::Success);
        steps.push(ScriptedInvocationStep::new(
            InvocationOperation::ReadPropertiesAfterKill,
            ScriptedInvocationResponse::NoSuchUnit,
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
            PayloadScopeError::InvocationUnavailable
        );
        backend.assert_consumed();
    }

    #[test]
    fn replacement_path_after_kill_is_identity_change() {
        let mut steps = kill_steps(ScriptedInvocationResponse::Success);
        steps.push(ScriptedInvocationStep::new(
            InvocationOperation::ReadPropertiesAfterKill,
            ScriptedInvocationResponse::Properties(InvocationUnitProperties {
                object_path: path_b(),
                invocation_id: INVOCATION_B.into(),
                ..properties_a()
            }),
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
            PayloadScopeError::UnitReplaced
        );
        backend.assert_consumed();
    }

