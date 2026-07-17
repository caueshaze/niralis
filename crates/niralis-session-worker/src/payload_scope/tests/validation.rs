    #[test]
    fn rejects_broad_or_wrong_scope_paths() {
        assert!(!valid_payload_cgroup(
            "/user.slice",
            1000,
            "niralis-payload-a.scope"
        ));
        assert!(!valid_payload_cgroup(
            "/user.slice/user-1000.slice",
            1000,
            "niralis-payload-a.scope"
        ));
        assert!(!valid_payload_cgroup(
            "/user.slice/user-1000.slice/session-3.scope",
            1000,
            "session-3.scope"
        ));
        assert!(valid_payload_cgroup(
            "/user.slice/user-1000.slice/niralis-payload-a.scope",
            1000,
            "niralis-payload-a.scope"
        ));
    }

    #[test]
    fn parses_only_unified_membership() {
        assert_eq!(
            parse_unified_cgroup("0::/user.slice/a.scope\n").unwrap(),
            "/user.slice/a.scope"
        );
        assert!(parse_unified_cgroup("2:cpu:/legacy\n").is_err());
    }

    #[test]
    fn invocation_id_round_trips_as_dbus_bytes() {
        let value = "00112233445566778899aabbccddeeff";
        let bytes = parse_hex_id(value).unwrap();
        assert_eq!(hex_id(&bytes).as_deref(), Some(value));
        assert!(parse_hex_id("0011").is_none());
        assert!(parse_hex_id("zz112233445566778899aabbccddeeff").is_none());
    }

    #[test]
    fn running_termination_has_no_manager_killunit_fallback() {
        let source = include_str!("../zbus_provider.rs");
        assert!(!source.contains("\"KillUnit\""));
        assert!(source.contains("\"GetUnitByInvocationID\""));
        assert!(source.contains("\"Kill\", &(\"all\", signal)"));
    }

    #[test]
    fn cgroup_events_parser_is_bounded_and_requires_unique_populated_state() {
        assert_eq!(parse_populated("frozen 0\npopulated 0\n"), Ok(0));
        assert_eq!(parse_populated("populated 1\nfrozen 0\n"), Ok(1));
        assert_eq!(
            parse_populated("frozen 0\n"),
            Err(PayloadScopeError::InvalidMembership)
        );
        assert_eq!(
            parse_populated("populated x\n"),
            Err(PayloadScopeError::InvalidMembership)
        );
        assert_eq!(
            parse_populated("populated 0\npopulated 0\n"),
            Err(PayloadScopeError::InvalidMembership)
        );
    }

    #[test]
    fn unit_terminal_states_are_explicit() {
        assert!(terminal_unit_state("inactive", "dead"));
        assert!(terminal_unit_state("failed", "failed"));
        for state in [
            ("active", "running"),
            ("active", "exited"),
            ("activating", "start"),
            ("deactivating", "stop-sigterm"),
            ("inactive", "failed"),
        ] {
            assert!(!terminal_unit_state(state.0, state.1), "{state:?}");
        }
    }

    #[test]
    fn bounded_reader_rejects_oversized_state() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state");
        std::fs::write(&path, vec![b'x'; MAX_CGROUP_STATE_BYTES as usize + 1]).unwrap();
        assert_eq!(
            read_bounded(&path).err(),
            Some(PayloadScopeError::InvalidMembership)
        );
    }

    #[test]
    fn empty_cgroup_requires_populated_zero_and_empty_procs() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("user.slice/user-1000.slice/test.scope");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
        std::fs::write(directory.join("cgroup.procs"), "").unwrap();
        assert!(matches!(
            read_cgroup_empty_state_at(root.path(), "/user.slice/user-1000.slice/test.scope"),
            Ok(CgroupEmptyState::PresentEmpty)
        ));

        std::fs::write(directory.join("cgroup.events"), "populated 1\n").unwrap();
        assert_eq!(
            read_cgroup_empty_state_at(root.path(), "/user.slice/user-1000.slice/test.scope").err(),
            Some(PayloadScopeError::BoundaryNotEmpty)
        );
        std::fs::write(directory.join("cgroup.events"), "populated 0\n").unwrap();
        std::fs::write(directory.join("cgroup.procs"), "4242\n").unwrap();
        assert_eq!(
            read_cgroup_empty_state_at(root.path(), "/user.slice/user-1000.slice/test.scope").err(),
            Some(PayloadScopeError::BoundaryNotEmpty)
        );
    }

    #[test]
    fn absent_original_cgroup_is_distinct_from_unreadable_state() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_cgroup_empty_state_at(root.path(), "/missing.scope"),
            Ok(CgroupEmptyState::Absent)
        ));
        let directory = root.path().join("present.scope");
        std::fs::create_dir_all(&directory).unwrap();
        assert_eq!(
            read_cgroup_empty_state_at(root.path(), "/present.scope").err(),
            Some(PayloadScopeError::InvalidMembership)
        );
    }
