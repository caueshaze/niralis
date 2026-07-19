use super::*;

pub(crate) fn prove_startup_absent_boundary(
    record: &PersistentRecoveryRecord,
    identity: &crate::PayloadScopeIdentity,
    leader: &PersistedProcessIdentity,
    owner_watch: &OwnerWatch,
) -> Result<(), StartupRecoveryFailure> {
    let expected_control_group = format!(
        "/user.slice/user-{}.slice/{}",
        identity.expected_uid, identity.unit_name
    );
    let expected_slice = format!("user-{}.slice", identity.expected_uid);
    if matches!(leader, PersistedProcessIdentity::OriginalStillAlive { .. })
        || record.transient != Some(true)
        || record.payload_unit.as_deref() != Some(identity.unit_name.as_str())
        || record.control_group.as_deref() != Some(expected_control_group.as_str())
        || record.slice.as_deref() != Some(expected_slice.as_str())
    {
        return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
    }
    let control_group = record
        .control_group
        .as_deref()
        .ok_or(StartupRecoveryFailure::BoundaryIdentityChanged)?;
    owner_watch
        .stable()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    let owner =
        systemd_owner(&connection).map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    ensure_outside_boundary(record.worker_pid, control_group)
        .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    ensure_outside_boundary(record.launcher_pid, control_group)
        .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    for _ in 0..2 {
        owner_watch
            .stable()
            .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
        if resolve_invocation(&connection, &identity.invocation_id)
            .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?
            .is_some()
            || !matches!(
                read_supervisor_boundary_state(control_group),
                Ok(SupervisorBoundaryState::Absent)
            )
        {
            return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
        }
        if systemd_owner(&connection).map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?
            != owner
        {
            return Err(StartupRecoveryFailure::SystemdOwnerChanged);
        }
    }
    owner_watch
        .stable()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    info!(
        lifecycle_id = %record.lifecycle_id,
        invocation_id = %identity.invocation_id,
        "startup coherent absent-boundary proof established"
    );
    Ok(())
}
