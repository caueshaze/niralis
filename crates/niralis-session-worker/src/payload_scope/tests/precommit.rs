    #[test]
    fn precommit_cgroup_disappearance_requires_two_coherent_invocation_resolutions() {
        let mut terminal = terminal_properties_a();
        terminal.control_group.clear();
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryState(CgroupEmptyState::Absent),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringCleanup,
                ScriptedInvocationResponse::Properties(terminal.clone()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringCleanup,
                ScriptedInvocationResponse::Properties(terminal),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::UnrefPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
        ]);
        assert_eq!(
            backend
                .read_boundary_state(INVOCATION_A, &path_a(), CONTROL_GROUP)
                .unwrap(),
            CgroupEmptyState::Absent
        );
        let mut pinned = pinned_a();
        async_io::block_on(prove_precommit_disappearance(
            &backend,
            &identity_a(),
            &pinned,
            CONTROL_GROUP,
        ))
        .unwrap();
        async_io::block_on(release_pin(&backend, &identity_a(), &mut pinned)).unwrap();
        assert!(!pinned.reference_held);
        backend.assert_consumed();
    }

    #[test]
    fn replacement_between_precommit_disappearance_revalidations_preserves_pin() {
        let mut terminal = terminal_properties_a();
        terminal.control_group.clear();
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringCleanup,
                ScriptedInvocationResponse::Properties(terminal),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_b()),
            ),
        ]);
        let pinned = pinned_a();
        assert_eq!(
            async_io::block_on(prove_precommit_disappearance(
                &backend,
                &identity_a(),
                &pinned,
                CONTROL_GROUP,
            )),
            Err(PayloadScopeError::UnitReplaced)
        );
        assert!(pinned.reference_held);
        backend.assert_consumed();
    }

    #[test]
    fn invocation_removed_before_resolve_never_falls_back_to_name() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::NoSuchUnit,
        )]);
        let error = async_io::block_on(request_graceful_termination_invocation(
            &backend,
            &identity_a(),
            &pinned_a(),
            CONTROL_GROUP,
        ))
        .unwrap_err();
        assert_eq!(error, PayloadScopeError::InvocationUnavailable);
        backend.assert_consumed();
    }

    #[test]
    fn invocation_removed_between_resolve_and_ref_never_kills() {
        for response in [
            ScriptedInvocationResponse::UnknownObject,
            ScriptedInvocationResponse::NoSuchUnit,
        ] {
            let backend = ScriptedInvocationBackend::new(vec![
                ScriptedInvocationStep::new(
                    InvocationOperation::ResolveByInvocation,
                    ScriptedInvocationResponse::Resolved(path_a()),
                ),
                ScriptedInvocationStep::new(InvocationOperation::RefPinnedUnit, response),
            ]);
            let error = async_io::block_on(pin_invocation_unit(
                &backend,
                UNIT_NAME,
                INVOCATION_A,
                CONTROL_GROUP,
                "user-1000.slice",
            ))
            .unwrap_err();
            assert_eq!(error, PayloadScopeError::InvocationUnavailable);
            backend.assert_consumed();
        }
    }

    fn assert_post_ref_mismatch(properties: InvocationUnitProperties) {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::RefPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterRef,
                ScriptedInvocationResponse::Properties(properties),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::UnrefPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
        ]);
        assert_eq!(
            async_io::block_on(pin_invocation_unit(
                &backend,
                UNIT_NAME,
                INVOCATION_A,
                CONTROL_GROUP,
                "user-1000.slice",
            ))
            .unwrap_err(),
            PayloadScopeError::UnitReplaced
        );
        backend.assert_consumed();
    }

    #[test]
    fn post_ref_invocation_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            invocation_id: INVOCATION_B.into(),
            ..properties_a()
        });
    }

    #[test]
    fn post_ref_unit_id_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            id: "replacement.scope".into(),
            ..properties_a()
        });
    }

    #[test]
    fn post_ref_control_group_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            control_group: "/user.slice/user-1000.slice/replacement.scope".into(),
            ..properties_a()
        });
    }

    #[test]
    fn post_ref_slice_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            slice: "system.slice".into(),
            ..properties_a()
        });
    }

    #[test]
    fn post_ref_non_transient_unit_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            transient: false,
            ..properties_a()
        });
    }

