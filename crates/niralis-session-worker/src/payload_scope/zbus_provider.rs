
impl InvocationBoundProvider for ZbusInvocationProvider {
    fn resolve_by_invocation<'a>(
        &'a self,
        expected_invocation_id: &'a str,
    ) -> InvocationFuture<'a, OwnedObjectPath> {
        Box::pin(async move {
            let manager = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                SYSTEMD_PATH,
                SYSTEMD_MANAGER,
            )
            .await
            .map_err(classify_zbus_error)?;
            let bytes =
                parse_hex_id(expected_invocation_id).ok_or(InvocationBackendError::Transport)?;
            manager
                .call("GetUnitByInvocationID", &(bytes,))
                .await
                .map_err(classify_zbus_error)
        })
    }

    fn ref_pinned_unit<'a>(
        &'a self,
        _expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
    ) -> InvocationFuture<'a, ()> {
        Box::pin(async move {
            let unit = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_UNIT,
            )
            .await
            .map_err(classify_zbus_error)?;
            unit.call::<_, _, ()>("Ref", &())
                .await
                .map_err(classify_zbus_error)
        })
    }

    fn read_properties<'a>(
        &'a self,
        _operation: InvocationOperation,
        _expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
        _expected_unit_name: &'a str,
    ) -> InvocationFuture<'a, InvocationUnitProperties> {
        Box::pin(async move {
            let unit = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_UNIT,
            )
            .await
            .map_err(classify_zbus_error)?;
            let scope = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_SCOPE,
            )
            .await
            .map_err(classify_zbus_error)?;
            let invocation: Vec<u8> = unit
                .get_property("InvocationID")
                .await
                .map_err(classify_zbus_error)?;
            Ok(InvocationUnitProperties {
                object_path: expected_object_path.clone(),
                id: unit.get_property("Id").await.map_err(classify_zbus_error)?,
                invocation_id: hex_id(&invocation).ok_or(InvocationBackendError::Transport)?,
                control_group: scope
                    .get_property("ControlGroup")
                    .await
                    .map_err(classify_zbus_error)?,
                slice: scope
                    .get_property("Slice")
                    .await
                    .map_err(classify_zbus_error)?,
                transient: unit
                    .get_property("Transient")
                    .await
                    .map_err(classify_zbus_error)?,
                active_state: unit
                    .get_property("ActiveState")
                    .await
                    .map_err(classify_zbus_error)?,
                sub_state: unit
                    .get_property("SubState")
                    .await
                    .map_err(classify_zbus_error)?,
            })
        })
    }

    fn kill_pinned_unit<'a>(
        &'a self,
        _expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
        signal: libc::c_int,
    ) -> InvocationFuture<'a, ()> {
        Box::pin(async move {
            let unit = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_UNIT,
            )
            .await
            .map_err(classify_zbus_error)?;
            unit.call::<_, _, ()>("Kill", &("all", signal))
                .await
                .map_err(classify_zbus_error)
        })
    }

    fn create_boundary_observer(
        &self,
        _expected_invocation_id: &str,
        _expected_object_path: &OwnedObjectPath,
        control_group: &str,
    ) -> Result<Box<dyn PayloadBoundaryObserver>, InvocationBackendError> {
        CgroupEventsObserver::open(control_group)
            .map(|observer| Box::new(observer) as Box<dyn PayloadBoundaryObserver>)
            .map_err(|_| InvocationBackendError::Transport)
    }

    fn read_boundary_state(
        &self,
        _expected_invocation_id: &str,
        _expected_object_path: &OwnedObjectPath,
        control_group: &str,
    ) -> Result<CgroupEmptyState, InvocationBackendError> {
        read_cgroup_empty_state(control_group).map_err(|error| match error {
            PayloadScopeError::BoundaryNotEmpty => InvocationBackendError::BoundaryNotEmpty,
            PayloadScopeError::InvalidIdentity => InvocationBackendError::CgroupAbsent,
            _ => InvocationBackendError::CgroupIo,
        })
    }

    fn unref_pinned_unit<'a>(
        &'a self,
        _expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
    ) -> InvocationFuture<'a, ()> {
        Box::pin(async move {
            let unit = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_UNIT,
            )
            .await
            .map_err(classify_zbus_error)?;
            unit.call::<_, _, ()>("Unref", &())
                .await
                .map_err(classify_zbus_error)
        })
    }
}

fn map_invocation_error(
    operation: InvocationOperation,
    error: InvocationBackendError,
) -> PayloadScopeError {
    let mapped = match error {
        InvocationBackendError::NoSuchUnit | InvocationBackendError::UnknownObject => {
            PayloadScopeError::InvocationUnavailable
        }
        InvocationBackendError::BusDisconnected => PayloadScopeError::BusUnavailable,
        InvocationBackendError::ServiceOwnerChanged => PayloadScopeError::ServiceOwnerChanged,
        InvocationBackendError::Transport => PayloadScopeError::TransportFailure,
        InvocationBackendError::BoundaryNotEmpty => PayloadScopeError::BoundaryNotEmpty,
        InvocationBackendError::CgroupAbsent => PayloadScopeError::InvalidIdentity,
        InvocationBackendError::CgroupIo => PayloadScopeError::InvalidMembership,
    };
    match mapped {
        PayloadScopeError::BusUnavailable | PayloadScopeError::ServiceOwnerChanged => {
            warn!(
                stage = operation.stage(),
                "system bus lost during invocation-bound operation"
            );
        }
        PayloadScopeError::InvocationUnavailable | PayloadScopeError::TransportFailure => {
            warn!(
                stage = operation.stage(),
                "invocation-bound unit operation failed"
            );
        }
        _ => {}
    }
    mapped
}

fn validate_pinned_properties(
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    properties: &InvocationUnitProperties,
) -> Result<(), PayloadScopeError> {
    validate_pinned_properties_with_control_group(
        identity,
        pinned,
        control_group,
        properties,
        ControlGroupPropertyMode::Exact,
    )
}
