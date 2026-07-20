use super::*;

pub(crate) fn reconcile_same_boot_record(
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
) -> StartupRecoveryOutcome {
    match rehydrate_process_identity(
        record.worker_pid,
        record.worker_starttime,
        record.worker_executable,
        record.worker_cgroup.as_deref(),
    ) {
        PersistedProcessIdentity::OriginalStillAlive { pidfd } => {
            info!(lifecycle_id = %record.lifecycle_id, "surviving worker observed after supervisor restart");
            if wait_for_pidfd(pidfd.as_raw_fd(), 1000).unwrap_or(false) {
                PersistedProcessIdentity::OriginalGone
            } else {
                if matches!(
                    record.operation_ledger.runtime_release,
                    DurableOperationState::IntentPersisted { .. }
                        | DurableOperationState::Indeterminate { .. }
                ) {
                    return StartupRecoveryOutcome::Quarantined(
                        StartupRecoveryFailure::WorkerIdentityIndeterminate,
                    );
                }
                let attempt = record.sequence.saturating_add(1);
                if ledger
                    .operation_intent(&record.lifecycle_id, "runtime_release", attempt)
                    .is_err()
                {
                    return StartupRecoveryOutcome::Quarantined(
                        StartupRecoveryFailure::UnsupportedRehydration,
                    );
                }
                if send_sigterm(pidfd.as_raw_fd()).is_err()
                    || !wait_for_pidfd(pidfd.as_raw_fd(), 1000).unwrap_or(false)
                {
                    return StartupRecoveryOutcome::Quarantined(
                        StartupRecoveryFailure::WorkerIdentityIndeterminate,
                    );
                }
                if ledger
                    .operation_confirmed(&record.lifecycle_id, "runtime_release", attempt)
                    .is_err()
                {
                    return StartupRecoveryOutcome::Quarantined(
                        StartupRecoveryFailure::UnsupportedRehydration,
                    );
                }
                PersistedProcessIdentity::OriginalGone
            }
        }
        PersistedProcessIdentity::OriginalGone => PersistedProcessIdentity::OriginalGone,
        PersistedProcessIdentity::PidReused | PersistedProcessIdentity::Indeterminate => {
            return StartupRecoveryOutcome::Quarantined(
                StartupRecoveryFailure::WorkerIdentityIndeterminate,
            )
        }
    };
    let leader = match (record.leader_pid, record.leader_starttime) {
        (Some(pid), starttime) => rehydrate_process_identity(
            pid,
            starttime,
            record.leader_executable,
            record.control_group.as_deref(),
        ),
        _ => {
            return StartupRecoveryOutcome::Quarantined(
                StartupRecoveryFailure::LeaderIdentityIndeterminate,
            )
        }
    };
    if matches!(leader, PersistedProcessIdentity::Indeterminate) {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::LeaderIdentityIndeterminate,
        );
    }
    let Some(unit_name) = record.payload_unit.clone() else {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    };
    let Some(invocation_id) = record.invocation_id.clone() else {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    };
    let Some(session_id) = record
        .logind_session_id
        .as_deref()
        .and_then(|id| crate::LogindSessionId::new(id.to_owned()))
    else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::LogindIdentityChanged);
    };
    let identity = crate::PayloadScopeIdentity {
        unit_name,
        invocation_id,
        expected_uid: record.uid,
        logind_session_id: session_id,
    };
    if record.transient != Some(true) || !identity.validate() {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
    let (systemd_watch, logind_watch) = match open_recovery_owner_watches() {
        Ok(watches) => watches,
        Err(_) => {
            return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::SystemdOwnerChanged)
        }
    };
    let mut pin = match SupervisorPinnedInvocationUnit::rehydrate(
        identity.clone(),
        record.worker_pid,
        record.launcher_pid,
    ) {
        Ok(pin) => pin,
        Err(SupervisorRecoveryError::BusUnavailable) => {
            return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::SystemdOwnerChanged)
        }
        Err(SupervisorRecoveryError::BoundaryIdentityChanged) => {
            if let Err(reason) =
                prove_startup_absent_boundary(record, &identity, &leader, &systemd_watch)
            {
                return StartupRecoveryOutcome::Quarantined(reason);
            }
            if let Err(reason) =
                confirm_absent_boundary_logind_and_vt(record, ledger, &logind_watch)
            {
                return StartupRecoveryOutcome::Quarantined(reason);
            }
            return StartupRecoveryOutcome::Free;
        }
        Err(_) => {
            return StartupRecoveryOutcome::Quarantined(
                StartupRecoveryFailure::BoundaryIdentityChanged,
            )
        }
    };
    if let Err(reason) = reconcile_payload(record, &mut pin, &leader, ledger, &systemd_watch) {
        let _ = pin.release();
        return StartupRecoveryOutcome::Quarantined(reason);
    }
    let unref_attempt = record.sequence.saturating_add(4);
    if ledger
        .operation_intent(&record.lifecycle_id, "supervisor_unref", unref_attempt)
        .is_err()
    {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::UnsupportedRehydration);
    }
    if pin.release().is_err() {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
    if ledger
        .operation_confirmed(&record.lifecycle_id, "supervisor_unref", unref_attempt)
        .is_err()
    {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::UnsupportedRehydration);
    }
    if let Err(reason) = reconcile_logind_and_vt(record, ledger, &logind_watch) {
        return StartupRecoveryOutcome::Quarantined(reason);
    }
    StartupRecoveryOutcome::Free
}
fn reconcile_payload(
    record: &PersistentRecoveryRecord,
    pin: &mut SupervisorPinnedInvocationUnit,
    leader: &PersistedProcessIdentity,
    ledger: &mut PersistentRecoveryLedger,
    owner_watch: &OwnerWatch,
) -> Result<(), StartupRecoveryFailure> {
    if matches!(
        pin.boundary_state()
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?,
        SupervisorBoundaryState::Populated
    ) {
        owner_watch
            .stable()
            .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
        if matches!(
            record.operation_ledger.payload_kill,
            DurableOperationState::IntentPersisted { .. }
                | DurableOperationState::Indeterminate { .. }
        ) {
            return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
        }
        let attempt = record.sequence.saturating_add(1);
        ledger
            .operation_intent(&record.lifecycle_id, "payload_kill", attempt)
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
        pin.request_emergency_kill()
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
        wait_for_boundary_empty(pin, owner_watch)?;
        ledger
            .operation_confirmed(&record.lifecycle_id, "payload_kill", attempt)
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
    }
    if matches!(leader, PersistedProcessIdentity::OriginalStillAlive { .. }) {
        return Err(StartupRecoveryFailure::LeaderIdentityIndeterminate);
    }
    owner_watch
        .stable()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    startup_boundary_proof(pin, owner_watch)
}
