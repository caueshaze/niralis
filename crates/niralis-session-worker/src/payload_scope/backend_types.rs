
struct SystemdPayloadScope {
    connection: zbus::Connection,
    invocation_provider: std::sync::Arc<dyn InvocationBoundProvider>,
    identity: PayloadScopeIdentity,
    pinned_unit: PinnedInvocationUnit,
    control_group: String,
    worker_pid: u32,
    launcher_pid: u32,
}

#[derive(Debug)]
struct PinnedInvocationUnit {
    object_path: OwnedObjectPath,
    reference_held: bool,
}

#[derive(Clone)]
struct ZbusInvocationProvider {
    connection: zbus::Connection,
}

impl ZbusInvocationProvider {
    fn new(connection: &zbus::Connection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }
}

fn classify_zbus_error(error: zbus::Error) -> InvocationBackendError {
    match error {
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
        {
            InvocationBackendError::NoSuchUnit
        }
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.UnknownObject" =>
        {
            InvocationBackendError::UnknownObject
        }
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.NameHasNoOwner" =>
        {
            InvocationBackendError::ServiceOwnerChanged
        }
        zbus::Error::MethodError(name, _, _)
            if matches!(
                name.as_str(),
                "org.freedesktop.DBus.Error.Disconnected" | "org.freedesktop.DBus.Error.NoReply"
            ) =>
        {
            InvocationBackendError::BusDisconnected
        }
        zbus::Error::InputOutput(_) => InvocationBackendError::BusDisconnected,
        zbus::Error::FDO(error)
            if matches!(error.as_ref(), zbus::fdo::Error::NameHasNoOwner(_)) =>
        {
            InvocationBackendError::ServiceOwnerChanged
        }
        zbus::Error::FDO(error)
            if matches!(
                error.as_ref(),
                zbus::fdo::Error::Disconnected(_) | zbus::fdo::Error::NoReply(_)
            ) =>
        {
            InvocationBackendError::BusDisconnected
        }
        _ => InvocationBackendError::Transport,
    }
}
