use super::*;

pub(crate) fn inventory_unknown_payload_scopes(
    records: &[PersistentRecoveryRecord],
) -> Result<UnknownScopeInventory, StartupRecoveryFailure> {
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| StartupRecoveryFailure::UnknownPayloadScope)?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| StartupRecoveryFailure::UnknownPayloadScope)?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .map_err(|_| StartupRecoveryFailure::UnknownPayloadScope)?;
    let units: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        OwnedObjectPath,
        u32,
        String,
        OwnedObjectPath,
    )> = manager
        .call("ListUnits", &())
        .map_err(|_| StartupRecoveryFailure::UnknownPayloadScope)?;
    let mut unknown = false;
    for (id, _, _, _, _, _, path, _, _, _) in units {
        if !id.starts_with("niralis-payload-") || !id.ends_with(".scope") {
            continue;
        }
        let known = records.iter().any(|record| {
            record.payload_unit.as_deref() == Some(id.as_str())
                || record.object_path.as_deref() == Some(path.as_str())
        });
        if !known {
            warn!(unit = %id, "unknown Niralis payload scope without durable record");
            unknown = true;
        }
    }
    if unknown {
        // The systemd unit inventory does not carry a trustworthy logind seat
        // identity.  Refusing all new logins is therefore the only safe Linux
        // result until an administrative reconciler can identify the owner.
        Ok(UnknownScopeInventory::GlobalQuarantine)
    } else {
        Ok(UnknownScopeInventory::None)
    }
}
