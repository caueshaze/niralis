use super::*;

pub(crate) fn reconcile_real_dbus_logind(
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
    provider: &SupervisorFixtureRecoveryProvider,
) -> StartupRecoveryOutcome {
    fixture_event(provider, "real_logind_begin");
    let (Some(session_id), Some(expected_path), Some(address)) = (
        record.logind_session_id.as_deref(),
        record.logind_object_path.as_deref(),
        std::env::var("NIRALIS_FIXTURE_DBUS_ADDRESS").ok(),
    ) else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    };
    let Ok((_, logind_watch)) = open_recovery_owner_watches_on_address(&address) else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    };
    let Ok(connection) = zbus::blocking::connection::Builder::system()
        .and_then(|builder| builder.method_timeout(Duration::from_secs(5)).build())
    else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    };
    let Ok(owner) = logind_owner() else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    };
    let Ok(manager) = zbus::blocking::Proxy::new(
        &connection,
        LOGIND_DESTINATION,
        LOGIND_MANAGER_PATH,
        LOGIND_MANAGER_INTERFACE,
    ) else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    };
    let prior_intent = matches!(
        record.operation_ledger.logind_termination,
        DurableOperationState::IntentPersisted { .. } | DurableOperationState::Indeterminate { .. }
    );
    let path =
        match manager.call::<_, _, zbus::zvariant::OwnedObjectPath>("GetSession", &(session_id,)) {
            Ok(path) => path,
            Err(_) if prior_intent => {
                fixture_event(provider, "logind_already_gone");
                fixture_event(provider, "vt_recovery");
                return StartupRecoveryOutcome::Free;
            }
            Err(_) => {
                return StartupRecoveryOutcome::Quarantined(
                    StartupRecoveryFailure::LogindIdentityChanged,
                )
            }
        };
    if prior_intent {
        fixture_event(provider, "quarantine:indeterminate_logind_termination");
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    }
    if path.as_str() != expected_path {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    }
    let Some(id) = crate::LogindSessionId::new(session_id.to_owned()) else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    };
    let Ok(identity) = read_logind_identity(&connection, &path, id) else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    };
    if identity.uid != record.uid
        || identity.leader != record.worker_pid
        || identity.seat != record.seat
        || Some(identity.vt_number) != record.target_vt
        || identity.username != record.username
        || identity.desktop != record.session_name
    {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    }
    if logind_watch.stable().is_err() {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    }
    let attempt = record.sequence.saturating_add(1);
    if ledger
        .operation_intent(&record.lifecycle_id, "logind_termination", attempt)
        .is_err()
    {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    }
    if manager
        .call::<_, _, ()>("TerminateSession", &(session_id,))
        .is_err()
    {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    }
    let still_present = manager
        .call::<_, _, zbus::zvariant::OwnedObjectPath>("GetSession", &(session_id,))
        .is_ok();
    if still_present
        || logind_owner().ok().as_deref() != Some(owner.as_str())
        || logind_watch.stable().is_err()
        || ledger
            .operation_confirmed(&record.lifecycle_id, "logind_termination", attempt)
            .is_err()
    {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    }
    fixture_event(provider, "logind_dbus_terminate_confirmed");
    fixture_event(provider, "vt_recovery");
    StartupRecoveryOutcome::Free
}

pub(crate) fn reconcile_real_dbus_logind_owner_change(
    record: &PersistentRecoveryRecord,
    _ledger: &mut PersistentRecoveryLedger,
    provider: &SupervisorFixtureRecoveryProvider,
) -> StartupRecoveryOutcome {
    let Some(address) = std::env::var_os("NIRALIS_FIXTURE_DBUS_ADDRESS") else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    };
    let Ok((_, logind_watch)) = open_recovery_owner_watches_on_address(&address.to_string_lossy())
    else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    };
    if record.logind_session_id.is_none() || record.logind_object_path.is_none() {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    }
    let Some(pid) = std::env::var("NIRALIS_FIXTURE_DBUS_OWNER_PID")
        .ok()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
    else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    };
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 || logind_watch.stable().is_ok() {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged);
    }
    fixture_event(provider, "owner_change:real_logind_before_terminate");
    StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindOwnerChanged)
}
