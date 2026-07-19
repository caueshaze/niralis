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
        .ok_or_else(|| previous_boot_conflict(record, "parse_invocation_id", None))?;
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|error| previous_boot_conflict(record, "open_system_bus", Some(&error)))?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|error| previous_boot_conflict(record, "connect_system_bus", Some(&error)))?;
    let owner = systemd_owner(&connection)
        .map_err(|error| previous_boot_conflict(record, "read_systemd_owner", Some(&error)))?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .map_err(|error| previous_boot_conflict(record, "create_systemd_manager", Some(&error)))?;
    let old_unit: Result<OwnedObjectPath, zbus::Error> =
        manager.call("GetUnitByInvocationID", &(invocation,));
    match old_unit {
        Ok(_) => {
            return Err(previous_boot_conflict(
                record,
                "invocation_still_resolves",
                None,
            ))
        }
        Err(zbus::Error::MethodError(name, _, _)) if is_absent_invocation_error(name.as_str()) => {}
        Err(error) => {
            return Err(previous_boot_conflict(
                record,
                "resolve_old_invocation",
                Some(&error),
            ))
        }
    }
    if systemd_owner(&connection).ok().as_deref() != Some(owner.as_str()) {
        warn!(lifecycle_id = %record.lifecycle_id, "previous-boot systemd owner changed");
        return Err(StartupRecoveryFailure::SystemdOwnerChanged);
    }
    let Some(control_group) = record.control_group.as_deref() else {
        return Err(previous_boot_conflict(
            record,
            "missing_control_group",
            None,
        ));
    };
    match read_supervisor_boundary_state(control_group) {
        Ok(SupervisorBoundaryState::Absent) => {}
        Ok(_) => return Err(previous_boot_conflict(record, "old_cgroup_present", None)),
        Err(error) => {
            return Err(previous_boot_conflict(
                record,
                "read_old_cgroup",
                Some(&error),
            ))
        }
    }
    if let Some(session_id) = record.logind_session_id.as_deref() {
        match logind_session_exists(session_id) {
            Ok(false) => {}
            Ok(true) => return Err(previous_boot_conflict(record, "old_session_present", None)),
            Err(error) => {
                return Err(previous_boot_conflict(
                    record,
                    "read_old_logind_session",
                    Some(&error),
                ))
            }
        }
    }
    Ok(())
}

fn previous_boot_conflict(
    record: &PersistentRecoveryRecord,
    stage: &'static str,
    error: Option<&dyn std::fmt::Debug>,
) -> StartupRecoveryFailure {
    match error {
        Some(error) => warn!(
            lifecycle_id = %record.lifecycle_id,
            stage,
            ?error,
            "previous-boot record cannot yet be cleared"
        ),
        None => warn!(
            lifecycle_id = %record.lifecycle_id,
            stage,
            "previous-boot record cannot yet be cleared"
        ),
    }
    StartupRecoveryFailure::PreviousBootConflict
}
