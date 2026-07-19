use super::*;

pub(crate) fn reconcile_linux_startup(
    record: &PersistentRecoveryRecord,
    relation: RecoveryBootRelation,
    ledger: &mut PersistentRecoveryLedger,
) -> StartupRecoveryOutcome {
    match relation {
        RecoveryBootRelation::SameBoot => reconcile_same_boot_record(record, ledger),
        RecoveryBootRelation::PreviousBoot => match clear_previous_boot_record(record) {
            Ok(()) => StartupRecoveryOutcome::Free,
            Err(reason) => StartupRecoveryOutcome::Quarantined(reason),
        },
    }
}

fn clear_previous_boot_record(
    record: &PersistentRecoveryRecord,
) -> Result<(), StartupRecoveryFailure> {
    let invocation = record
        .invocation_id
        .as_deref()
        .and_then(parse_invocation_id)
        .ok_or(StartupRecoveryFailure::PreviousBootConflict)?;
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| StartupRecoveryFailure::PreviousBootConflict)?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| StartupRecoveryFailure::PreviousBootConflict)?;
    let owner =
        systemd_owner(&connection).map_err(|_| StartupRecoveryFailure::PreviousBootConflict)?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .map_err(|_| StartupRecoveryFailure::PreviousBootConflict)?;
    let old_unit: Result<OwnedObjectPath, zbus::Error> =
        manager.call("GetUnitByInvocationID", &(invocation,));
    match old_unit {
        Ok(_) => return Err(StartupRecoveryFailure::PreviousBootConflict),
        Err(zbus::Error::MethodError(name, _, _))
            if matches!(
                name.as_str(),
                "org.freedesktop.systemd1.NoSuchUnit" | "org.freedesktop.DBus.Error.UnknownObject"
            ) => {}
        Err(_) => return Err(StartupRecoveryFailure::PreviousBootConflict),
    }
    if systemd_owner(&connection).ok().as_deref() != Some(owner.as_str()) {
        return Err(StartupRecoveryFailure::SystemdOwnerChanged);
    }
    let Some(control_group) = record.control_group.as_deref() else {
        return Err(StartupRecoveryFailure::PreviousBootConflict);
    };
    if !matches!(
        read_supervisor_boundary_state(control_group),
        Ok(SupervisorBoundaryState::Absent)
    ) {
        return Err(StartupRecoveryFailure::PreviousBootConflict);
    }
    if let Some(session_id) = record.logind_session_id.as_deref() {
        if logind_session_exists(session_id)
            .map_err(|_| StartupRecoveryFailure::PreviousBootConflict)?
        {
            return Err(StartupRecoveryFailure::PreviousBootConflict);
        }
    }
    Ok(())
}
