    #[test]
    fn service_owner_change_is_not_accepted_as_a_valid_pin() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::ServiceOwnerChanged,
        )]);
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::ServiceOwnerChanged
        );
        backend.assert_consumed();
    }

    #[test]
    fn typed_transport_cgroup_and_unref_failures_remain_distinct() {
        let transport = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::TransportFailure,
        )]);
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &transport,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::TransportFailure
        );
        transport.assert_consumed();

        let cgroup = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::NoSuchUnit,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::CgroupIoFailure,
            ),
        ]);
        assert_eq!(
            async_io::block_on(prove_empty_boundary(
                &cgroup,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
                u32::MAX,
                u32::MAX,
                &crate::termination::LeaderExit::ExitedZero,
            ))
            .unwrap_err(),
            PayloadScopeError::InvalidMembership
        );
        cgroup.assert_consumed();

        let unref = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::UnrefPinnedUnit,
            ScriptedInvocationResponse::UnrefFailure,
        )]);
        let mut pinned = pinned_a();
        assert_eq!(
            async_io::block_on(release_pin(&unref, &identity_a(), &mut pinned)).unwrap_err(),
            PayloadScopeError::UnrefFailed
        );
        assert!(pinned.reference_held);
        unref.assert_consumed();
    }

    #[test]
    #[should_panic(expected = "scripted invocation operation out of order")]
    fn scripted_backend_rejects_wrong_operation_order() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ReadPropertiesAfterRef,
            ScriptedInvocationResponse::Properties(properties_a()),
        )]);
        let _ =
            async_io::block_on(backend.kill_pinned_unit(INVOCATION_A, &path_a(), libc::SIGTERM));
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn scripted_backend_rejects_wrong_object_path() {
        let mut step = ScriptedInvocationStep::new(
            InvocationOperation::RefPinnedUnit,
            ScriptedInvocationResponse::Success,
        );
        step.expected_object_path = Some(path_b());
        let backend = ScriptedInvocationBackend::new(vec![step]);
        let _ = async_io::block_on(backend.ref_pinned_unit(INVOCATION_A, &path_a()));
    }

    #[test]
    #[should_panic(expected = "unexpected invocation operation with no scripted step")]
    fn scripted_backend_rejects_duplicate_ref() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::RefPinnedUnit,
            ScriptedInvocationResponse::Success,
        )]);
        async_io::block_on(backend.ref_pinned_unit(INVOCATION_A, &path_a())).unwrap();
        let _ = async_io::block_on(backend.ref_pinned_unit(INVOCATION_A, &path_a()));
    }

    #[test]
    #[should_panic(expected = "steps left unconsumed")]
    fn scripted_backend_rejects_unconsumed_steps() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::Resolved(path_a()),
        )]);
        backend.assert_consumed();
    }

    #[test]
    fn manager_kill_unit_is_unrepresentable_in_running_provider() {
        let source = concat!(
            include_str!("../contracts.rs"),
            include_str!("../backend_types.rs"),
            include_str!("../zbus_provider.rs"),
            include_str!("../prepare.rs"),
        );
        let provider = source
            .split("trait InvocationBoundProvider")
            .nth(1)
            .unwrap()
            .split("impl InvocationBoundProvider for ZbusInvocationProvider")
            .next()
            .unwrap();
        assert!(!provider.contains("kill_unit_by_name"));
        assert_eq!(provider.matches("fn kill_pinned_unit").count(), 1);
        assert!(!source.contains("\"KillUnit\""));
        assert!(source.contains("unit.call::<_, _, ()>(\"Kill\", &(\"all\", signal))"));
    }

    #[test]
    fn scripted_backend_is_test_only_and_not_runtime_selectable() {
        let source = concat!(
            include_str!("../contracts.rs"),
            include_str!("../backend_types.rs"),
            include_str!("../zbus_provider.rs"),
            include_str!("../identity_scope.rs"),
            include_str!("../termination_observer.rs"),
            include_str!("../empty_proof.rs"),
            include_str!("../prepare.rs"),
            include_str!("../cleanup.rs"),
            include_str!("../cgroup.rs"),
        );
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let main = include_str!("../../main.rs");
        let protocol = include_str!("../../../../niralis-session/src/protocol.rs");
        assert!(!production.contains("ScriptedInvocationBackend"));
        assert!(!production.contains("NIRALIS_SYSTEMD_BACKEND"));
        assert!(!main.contains("NIRALIS_SYSTEMD_BACKEND"));
        assert!(!protocol.contains("ScriptedInvocation"));
        assert!(production.contains("ZbusInvocationProvider::new(&connection)"));
    }
