use super::*;

pub(crate) fn systemd_owner(
    connection: &zbus::blocking::Connection,
) -> Result<String, SupervisorRecoveryError> {
    let proxy = zbus::blocking::Proxy::new(connection, DBUS_DESTINATION, DBUS_PATH, DBUS_INTERFACE)
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    proxy
        .call("GetNameOwner", &(SYSTEMD_DESTINATION,))
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)
}

pub(crate) fn resolve_invocation(
    connection: &zbus::blocking::Connection,
    invocation_id: &str,
) -> Result<Option<OwnedObjectPath>, SupervisorRecoveryError> {
    let invocation = parse_invocation_id(invocation_id)
        .ok_or(SupervisorRecoveryError::InvalidPayloadIdentity)?;
    let manager = zbus::blocking::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    match manager.call("GetUnitByInvocationID", &(invocation,)) {
        Ok(path) => Ok(Some(path)),
        Err(zbus::Error::MethodError(name, _, _))
            if matches!(
                name.as_str(),
                "org.freedesktop.systemd1.NoSuchUnit" | "org.freedesktop.DBus.Error.UnknownObject"
            ) =>
        {
            Ok(None)
        }
        Err(_) => Err(SupervisorRecoveryError::BusUnavailable),
    }
}

pub(crate) fn unit_call<A>(
    connection: &zbus::blocking::Connection,
    path: &OwnedObjectPath,
    method: &str,
    args: &A,
) -> Result<(), SupervisorRecoveryError>
where
    A: serde::ser::Serialize + zbus::zvariant::DynamicType,
{
    let unit = zbus::blocking::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        path.as_str(),
        SYSTEMD_UNIT_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    unit.call::<_, _, ()>(method, args)
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)
}

pub(crate) fn read_unit_observation(
    connection: &zbus::blocking::Connection,
    path: &OwnedObjectPath,
) -> Result<SupervisorUnitObservation, SupervisorRecoveryError> {
    let unit = zbus::blocking::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        path.as_str(),
        SYSTEMD_UNIT_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    let scope = zbus::blocking::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        path.as_str(),
        SYSTEMD_SCOPE_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    let invocation: Vec<u8> = unit
        .get_property("InvocationID")
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    Ok(SupervisorUnitObservation {
        object_path: path.to_string(),
        id: unit
            .get_property("Id")
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?,
        invocation_id: invocation
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        control_group: scope
            .get_property("ControlGroup")
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?,
        slice: scope
            .get_property("Slice")
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?,
        transient: unit
            .get_property("Transient")
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?,
        active_state: unit
            .get_property("ActiveState")
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?,
        sub_state: unit
            .get_property("SubState")
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?,
    })
}

pub(crate) fn validate_unit_observation(
    identity: &crate::PayloadScopeIdentity,
    observation: &SupervisorUnitObservation,
    terminal_control_group: Option<&str>,
) -> Result<(), SupervisorRecoveryError> {
    let expected_control_group = format!(
        "/user.slice/user-{}.slice/{}",
        identity.expected_uid, identity.unit_name
    );
    let control_group_matches = observation.control_group == expected_control_group
        || (terminal_control_group == Some(expected_control_group.as_str())
            && observation.control_group.is_empty()
            && unit_is_terminal(observation));
    if observation.id != identity.unit_name
        || observation.invocation_id != identity.invocation_id
        || observation.slice != format!("user-{}.slice", identity.expected_uid)
        || !observation.transient
        || !control_group_matches
    {
        return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
    }
    Ok(())
}

pub(crate) fn unit_is_terminal(observation: &SupervisorUnitObservation) -> bool {
    matches!(observation.active_state.as_str(), "inactive" | "failed")
        && matches!(observation.sub_state.as_str(), "dead" | "failed" | "exited")
}

pub(crate) fn parse_invocation_id(value: &str) -> Option<Vec<u8>> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..16)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok())
        .collect()
}
