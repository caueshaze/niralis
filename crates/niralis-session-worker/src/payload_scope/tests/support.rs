    use super::*;
    use std::collections::VecDeque;
    use std::os::fd::OwnedFd;
    use std::sync::Mutex;

    const INVOCATION_A: &str = "00112233445566778899aabbccddeeff";
    const INVOCATION_B: &str = "ffeeddccbbaa99887766554433221100";
    const UNIT_NAME: &str = "niralis-payload-00112233445566778899aabbccddeeff.scope";
    const CONTROL_GROUP: &str =
        "/user.slice/user-1000.slice/niralis-payload-00112233445566778899aabbccddeeff.scope";

    fn path_a() -> OwnedObjectPath {
        OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/path_a").unwrap()
    }

    fn path_b() -> OwnedObjectPath {
        OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/path_b").unwrap()
    }

    fn identity_a() -> PayloadScopeIdentity {
        PayloadScopeIdentity {
            unit_name: UNIT_NAME.into(),
            invocation_id: INVOCATION_A.into(),
            expected_uid: 1000,
            logind_session_id: LogindSessionId::new("fixture-session".into()).unwrap(),
        }
    }

    fn properties_a() -> InvocationUnitProperties {
        InvocationUnitProperties {
            object_path: path_a(),
            id: UNIT_NAME.into(),
            invocation_id: INVOCATION_A.into(),
            control_group: CONTROL_GROUP.into(),
            slice: "user-1000.slice".into(),
            transient: true,
            active_state: "active".into(),
            sub_state: "running".into(),
        }
    }

    fn terminal_properties_a() -> InvocationUnitProperties {
        InvocationUnitProperties {
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            ..properties_a()
        }
    }

    fn terminal_properties_with_cleared_control_group() -> InvocationUnitProperties {
        InvocationUnitProperties {
            control_group: String::new(),
            ..terminal_properties_a()
        }
    }

    #[derive(Debug)]
    enum ScriptedInvocationResponse {
        Success,
        Resolved(OwnedObjectPath),
        Properties(InvocationUnitProperties),
        BoundaryState(CgroupEmptyState),
        NoSuchUnit,
        UnknownObject,
        BusDisconnected,
        ServiceOwnerChanged,
        TransportFailure,
        BoundaryNotEmpty,
        CgroupIoFailure,
        UnrefFailure,
    }

    #[derive(Debug)]
    struct ScriptedInvocationStep {
        expected_operation: InvocationOperation,
        expected_invocation_id: String,
        expected_object_path: Option<OwnedObjectPath>,
        expected_unit_name: Option<String>,
        response: ScriptedInvocationResponse,
    }

    impl ScriptedInvocationStep {
        fn new(operation: InvocationOperation, response: ScriptedInvocationResponse) -> Self {
            Self {
                expected_operation: operation,
                expected_invocation_id: INVOCATION_A.into(),
                expected_object_path: (operation != InvocationOperation::ResolveByInvocation)
                    .then(path_a),
                expected_unit_name: matches!(
                    operation,
                    InvocationOperation::ReadPropertiesAfterRef
                        | InvocationOperation::ReadPropertiesAfterKill
                        | InvocationOperation::ReadPropertiesAfterObserver
                        | InvocationOperation::ReadPropertiesDuringEmptyProof
                        | InvocationOperation::ReadPropertiesDuringCleanup
                )
                .then(|| UNIT_NAME.into()),
                response,
            }
        }
    }

    struct ScriptedInvocationBackend {
        steps: Mutex<VecDeque<ScriptedInvocationStep>>,
    }

    impl ScriptedInvocationBackend {
        fn new(steps: Vec<ScriptedInvocationStep>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
            }
        }

        fn consume(
            &self,
            operation: InvocationOperation,
            invocation_id: &str,
            object_path: Option<&OwnedObjectPath>,
            unit_name: Option<&str>,
        ) -> ScriptedInvocationResponse {
            let mut steps = self.steps.lock().unwrap();
            let expected = steps.pop_front().unwrap_or_else(|| {
                panic!(
                    "unexpected invocation operation with no scripted step: observed={operation:?}({object_path:?})"
                )
            });
            assert_eq!(
                expected.expected_operation, operation,
                "scripted invocation operation out of order\nexpected: {:?}({:?})\nobserved: {:?}({:?})",
                expected.expected_operation,
                expected.expected_object_path,
                operation,
                object_path
            );
            assert_eq!(expected.expected_invocation_id, invocation_id);
            assert_eq!(expected.expected_object_path.as_ref(), object_path);
            assert_eq!(expected.expected_unit_name.as_deref(), unit_name);
            expected.response
        }

        fn assert_consumed(&self) {
            let steps = self.steps.lock().unwrap();
            assert!(
                steps.is_empty(),
                "scripted invocation steps left unconsumed: {steps:#?}"
            );
        }
    }

    fn response_error(response: ScriptedInvocationResponse) -> InvocationBackendError {
        match response {
            ScriptedInvocationResponse::NoSuchUnit => InvocationBackendError::NoSuchUnit,
            ScriptedInvocationResponse::UnknownObject => InvocationBackendError::UnknownObject,
            ScriptedInvocationResponse::BusDisconnected => InvocationBackendError::BusDisconnected,
            ScriptedInvocationResponse::ServiceOwnerChanged => {
                InvocationBackendError::ServiceOwnerChanged
            }
            ScriptedInvocationResponse::TransportFailure => InvocationBackendError::Transport,
            ScriptedInvocationResponse::BoundaryNotEmpty => {
                InvocationBackendError::BoundaryNotEmpty
            }
            ScriptedInvocationResponse::CgroupIoFailure => InvocationBackendError::CgroupIo,
            ScriptedInvocationResponse::UnrefFailure => InvocationBackendError::Transport,
            response => panic!("script response has wrong type for operation: {response:?}"),
        }
    }
