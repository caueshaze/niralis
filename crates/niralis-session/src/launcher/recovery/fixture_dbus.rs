use super::*;

pub(crate) fn reconcile_fixture_dbus(
    mode: SupervisorFixtureBoundaryMode,
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
    provider: &SupervisorFixtureRecoveryProvider,
) -> Option<StartupRecoveryOutcome> {
    match mode {
        SupervisorFixtureBoundaryMode::RealDbusPayloadRecovery => {
            Some(reconcile_real_dbus_payload(record, ledger, provider))
        }
        SupervisorFixtureBoundaryMode::RealDbusLogindCleanup => {
            Some(reconcile_real_dbus_logind(record, ledger, provider))
        }
        SupervisorFixtureBoundaryMode::RealDbusLogindOwnerChange => Some(
            reconcile_real_dbus_logind_owner_change(record, ledger, provider),
        ),
        _ => None,
    }
}

pub(crate) fn reconcile_real_dbus_payload(
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
    provider: &SupervisorFixtureRecoveryProvider,
) -> StartupRecoveryOutcome {
    fixture_event(provider, "real_dbus_begin");
    if matches!(
        record.operation_ledger.payload_kill,
        DurableOperationState::IntentPersisted { .. } | DurableOperationState::Indeterminate { .. }
    ) {
        fixture_event(provider, "quarantine:indeterminate_payload_kill");
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
    let (Some(unit), Some(invocation), Some(object_path), Some(cgroup), Some(leader_pid)) = (
        record.payload_unit.clone(),
        record.invocation_id.clone(),
        record.object_path.clone(),
        record.control_group.clone(),
        record.leader_pid,
    ) else {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    };
    let PersistedProcessIdentity::OriginalStillAlive { pidfd } = rehydrate_process_identity(
        leader_pid,
        record.leader_starttime,
        record.leader_executable,
        None,
    ) else {
        fixture_event(provider, "real_dbus_fail:leader_identity");
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::LeaderIdentityIndeterminate,
        );
    };
    let Ok(connection) = zbus::blocking::connection::Builder::system()
        .and_then(|builder| builder.method_timeout(Duration::from_secs(5)).build())
    else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::SystemdOwnerChanged);
    };
    let Ok(owner) = systemd_owner(&connection) else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::SystemdOwnerChanged);
    };
    let Ok(Some(path)) = resolve_invocation(&connection, &invocation) else {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    };
    if path.as_str() != object_path {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
    let Ok(first) = read_unit_observation(&connection, &path) else {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    };
    if first.id != unit
        || first.invocation_id != invocation
        || first.object_path != object_path
        || first.control_group != cgroup
        || first.slice != "user-1000.slice"
        || !first.transient
    {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
    if unit_call(&connection, &path, "Ref", &()).is_err() {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
    let second = resolve_invocation(&connection, &invocation)
        .ok()
        .flatten()
        .filter(|candidate| candidate.as_str() == object_path)
        .and_then(|candidate| read_unit_observation(&connection, &candidate).ok());
    if second.as_ref() != Some(&first)
        || systemd_owner(&connection).ok().as_deref() != Some(owner.as_str())
    {
        let _ = unit_call(&connection, &path, "Unref", &());
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::SystemdOwnerChanged);
    }
    let attempt = record.sequence.saturating_add(1);
    if ledger
        .operation_intent(&record.lifecycle_id, "payload_kill", attempt)
        .is_err()
        || unit_call(&connection, &path, "Kill", &("all", libc::SIGKILL)).is_err()
        || systemd_owner(&connection).ok().as_deref() != Some(owner.as_str())
        || !wait_for_pidfd(pidfd.as_raw_fd(), 1000).unwrap_or(false)
        || ledger
            .operation_confirmed(&record.lifecycle_id, "payload_kill", attempt)
            .is_err()
    {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
    fixture_event(
        provider,
        &format!("proof:startup_dbus unit={unit} invocation={invocation}"),
    );
    let unref_attempt = attempt.saturating_add(1);
    if ledger
        .operation_intent(&record.lifecycle_id, "supervisor_unref", unref_attempt)
        .is_err()
        || unit_call(&connection, &path, "Unref", &()).is_err()
        || ledger
            .operation_confirmed(&record.lifecycle_id, "supervisor_unref", unref_attempt)
            .is_err()
    {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
    fixture_event(provider, "logind_already_gone");
    fixture_event(provider, "vt_recovery");
    StartupRecoveryOutcome::Free
}
