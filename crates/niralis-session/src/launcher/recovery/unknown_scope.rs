use super::*;

type SystemdUnitListEntry = (
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
);

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
    let units: Vec<SystemdUnitListEntry> = manager
        .call("ListUnits", &())
        .map_err(|_| StartupRecoveryFailure::UnknownPayloadScope)?;
    let mut unknown = false;
    for (id, _, _, _, _, _, path, _, _, _) in units {
        if !id.starts_with("niralis-payload-") || !id.ends_with(".scope") {
            continue;
        }
        // Unit names and object paths are not identities on their own.  An
        // exact invocation match is required before startup may regard an
        // observed scope as represented by a durable record.  Ambiguity is
        // intentionally folded into the same non-destructive quarantine as a
        // wholly unknown scope.
        let listed_observation = read_unit_observation(&connection, &path)
            .map_err(|_| StartupRecoveryFailure::UnknownPayloadScope)?;
        // ListUnits and GetUnitByInvocationID may expose different D-Bus
        // object paths for the same live unit.  The durable pin deliberately
        // stores the latter because it is bound to the InvocationID.  Re-read
        // through that canonical path before deciding whether this scope is
        // represented by a record; otherwise a genuine live payload is
        // spuriously treated as unknown on restart.
        let Some(canonical_path) =
            resolve_invocation(&connection, &listed_observation.invocation_id)
                .map_err(|_| StartupRecoveryFailure::UnknownPayloadScope)?
        else {
            unknown = true;
            continue;
        };
        let observation = read_unit_observation(&connection, &canonical_path)
            .map_err(|_| StartupRecoveryFailure::UnknownPayloadScope)?;
        if listed_observation.id != observation.id
            || listed_observation.invocation_id != observation.invocation_id
            || listed_observation.control_group != observation.control_group
            || listed_observation.slice != observation.slice
            || listed_observation.transient != observation.transient
        {
            unknown = true;
            continue;
        }
        let candidates = records
            .iter()
            .filter(|record| {
                record.payload_unit.as_deref() == Some(id.as_str())
                    || record.object_path.as_deref() == Some(canonical_path.as_str())
                    || record.invocation_id.as_deref() == Some(observation.invocation_id.as_str())
            })
            .collect::<Vec<_>>();
        let known = candidates.len() == 1
            && candidates[0].payload_unit.as_deref() == Some(id.as_str())
            && candidates[0].object_path.as_deref() == Some(canonical_path.as_str())
            && candidates[0].invocation_id.as_deref() == Some(observation.invocation_id.as_str());
        if !known {
            warn!(
                unit = %id,
                invocation_id = %observation.invocation_id,
                candidates = candidates.len(),
                "unknown or conflicting Niralis payload scope without an exact durable identity"
            );
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
