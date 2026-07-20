use super::*;

pub(crate) fn open_recovery_owner_watches(
) -> Result<(OwnerWatch, OwnerWatch), SupervisorRecoveryError> {
    let systemd = systemd_owner(
        &zbus::blocking::connection::Builder::system()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?
            .method_timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?,
    )?;
    let logind = logind_owner()?;
    Ok((
        OwnerWatch::open(SYSTEMD_DESTINATION, systemd)?,
        OwnerWatch::open(LOGIND_DESTINATION, logind)?,
    ))
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) fn open_recovery_owner_watches_on_address(
    address: &str,
) -> Result<(OwnerWatch, OwnerWatch), SupervisorRecoveryError> {
    let connection = zbus::blocking::connection::Builder::address(address)
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    let dbus = zbus::blocking::Proxy::new(&connection, DBUS_DESTINATION, DBUS_PATH, DBUS_INTERFACE)
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    let owner = |name: &str| {
        dbus.call::<_, _, String>("GetNameOwner", &(name,))
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)
    };
    Ok((
        OwnerWatch::open_on_address(
            SYSTEMD_DESTINATION,
            owner(SYSTEMD_DESTINATION)?,
            Some(address.to_owned()),
        )?,
        OwnerWatch::open_on_address(
            LOGIND_DESTINATION,
            owner(LOGIND_DESTINATION)?,
            Some(address.to_owned()),
        )?,
    ))
}
