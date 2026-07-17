    impl InvocationBoundProvider for ScriptedInvocationBackend {
        fn resolve_by_invocation<'a>(
            &'a self,
            expected_invocation_id: &'a str,
        ) -> InvocationFuture<'a, OwnedObjectPath> {
            Box::pin(async move {
                match self.consume(
                    InvocationOperation::ResolveByInvocation,
                    expected_invocation_id,
                    None,
                    None,
                ) {
                    ScriptedInvocationResponse::Resolved(path) => Ok(path),
                    response => Err(response_error(response)),
                }
            })
        }

        fn ref_pinned_unit<'a>(
            &'a self,
            expected_invocation_id: &'a str,
            expected_object_path: &'a OwnedObjectPath,
        ) -> InvocationFuture<'a, ()> {
            Box::pin(async move {
                match self.consume(
                    InvocationOperation::RefPinnedUnit,
                    expected_invocation_id,
                    Some(expected_object_path),
                    None,
                ) {
                    ScriptedInvocationResponse::Success => Ok(()),
                    response => Err(response_error(response)),
                }
            })
        }

        fn read_properties<'a>(
            &'a self,
            operation: InvocationOperation,
            expected_invocation_id: &'a str,
            expected_object_path: &'a OwnedObjectPath,
            expected_unit_name: &'a str,
        ) -> InvocationFuture<'a, InvocationUnitProperties> {
            Box::pin(async move {
                match self.consume(
                    operation,
                    expected_invocation_id,
                    Some(expected_object_path),
                    Some(expected_unit_name),
                ) {
                    ScriptedInvocationResponse::Properties(properties) => Ok(properties),
                    response => Err(response_error(response)),
                }
            })
        }

        fn kill_pinned_unit<'a>(
            &'a self,
            expected_invocation_id: &'a str,
            expected_object_path: &'a OwnedObjectPath,
            signal: libc::c_int,
        ) -> InvocationFuture<'a, ()> {
            Box::pin(async move {
                assert_eq!(signal, libc::SIGTERM);
                match self.consume(
                    InvocationOperation::KillPinnedUnit,
                    expected_invocation_id,
                    Some(expected_object_path),
                    None,
                ) {
                    ScriptedInvocationResponse::Success => Ok(()),
                    response => Err(response_error(response)),
                }
            })
        }

        fn create_boundary_observer(
            &self,
            expected_invocation_id: &str,
            expected_object_path: &OwnedObjectPath,
            _control_group: &str,
        ) -> Result<Box<dyn PayloadBoundaryObserver>, InvocationBackendError> {
            match self.consume(
                InvocationOperation::CreateBoundaryObserver,
                expected_invocation_id,
                Some(expected_object_path),
                None,
            ) {
                ScriptedInvocationResponse::Success => {
                    let fd = unsafe { libc::eventfd(1, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
                    assert!(fd >= 0);
                    Ok(Box::new(ScriptedObserver(unsafe {
                        OwnedFd::from_raw_fd(fd)
                    })))
                }
                response => Err(response_error(response)),
            }
        }

        fn read_boundary_state(
            &self,
            expected_invocation_id: &str,
            expected_object_path: &OwnedObjectPath,
            _control_group: &str,
        ) -> Result<CgroupEmptyState, InvocationBackendError> {
            match self.consume(
                InvocationOperation::ReadBoundaryState,
                expected_invocation_id,
                Some(expected_object_path),
                None,
            ) {
                ScriptedInvocationResponse::BoundaryState(state) => Ok(state),
                response => Err(response_error(response)),
            }
        }

        fn unref_pinned_unit<'a>(
            &'a self,
            expected_invocation_id: &'a str,
            expected_object_path: &'a OwnedObjectPath,
        ) -> InvocationFuture<'a, ()> {
            Box::pin(async move {
                match self.consume(
                    InvocationOperation::UnrefPinnedUnit,
                    expected_invocation_id,
                    Some(expected_object_path),
                    None,
                ) {
                    ScriptedInvocationResponse::Success => Ok(()),
                    response => Err(response_error(response)),
                }
            })
        }
    }

    struct ScriptedObserver(OwnedFd);
    impl PayloadBoundaryObserver for ScriptedObserver {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
        fn poll_events(&self) -> libc::c_short {
            libc::POLLIN
        }
        fn consume_wakeup(&mut self) -> Result<(), PayloadScopeError> {
            let mut value = 0_u64;
            (unsafe { libc::read(self.0.as_raw_fd(), (&mut value as *mut u64).cast(), 8) } == 8)
                .then_some(())
                .ok_or(PayloadScopeError::ObserverFailed)
        }
    }

    fn pinned_a() -> PinnedInvocationUnit {
        PinnedInvocationUnit {
            object_path: path_a(),
            reference_held: true,
        }
    }

    fn kill_steps(kill_response: ScriptedInvocationResponse) -> Vec<ScriptedInvocationStep> {
        vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterRef,
                ScriptedInvocationResponse::Properties(properties_a()),
            ),
            ScriptedInvocationStep::new(InvocationOperation::KillPinnedUnit, kill_response),
        ]
    }
