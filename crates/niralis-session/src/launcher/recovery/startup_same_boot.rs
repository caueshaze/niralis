use super::*;

pub(crate) fn reconcile_same_boot_record(
    same_boot: &SameBootRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
) -> StartupRecoveryOutcome {
    let snapshot = same_boot.snapshot();
    let authority = &snapshot.authority;
    let record = &snapshot.record;
    if !authority.validates(record) {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
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
                if signal_validated_worker(authority, record, pidfd.as_raw_fd()).is_err()
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
    let mut pin = match RecoveryPinnedInvocationUnit::rehydrate(
        identity.clone(),
        record.worker_pid,
        record.launcher_pid,
        authority,
        record,
    ) {
        Ok(pin) => pin,
        Err(SupervisorRecoveryError::BusUnavailable)
        | Err(SupervisorRecoveryError::AuthorizationDenied { .. }) => {
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
    let (snapshot, boundary_proof) =
        match reconcile_payload(snapshot, &mut pin, &leader, ledger, &systemd_watch) {
            Ok(value) => value,
            Err(reason) => {
                return StartupRecoveryOutcome::Quarantined(reason);
            }
        };
    let unref_attempt = snapshot.record.sequence.saturating_add(1);
    let (snapshot, unref_permit, authorized_proof) =
        match ledger.persist_recovery_unref_intent(snapshot, boundary_proof, unref_attempt) {
            Ok(value) => value,
            Err(_) => {
                return StartupRecoveryOutcome::Quarantined(
                    StartupRecoveryFailure::UnsupportedRehydration,
                )
            }
        };
    if pin.rebind(&snapshot.authority, &snapshot.record).is_err()
        || pin
            .release_recovery(
                &snapshot.authority,
                &snapshot.record,
                unref_permit,
                &authorized_proof,
            )
            .is_err()
    {
        return StartupRecoveryOutcome::Quarantined(
            StartupRecoveryFailure::BoundaryIdentityChanged,
        );
    }
    if ledger
        .operation_confirmed(
            &snapshot.record.lifecycle_id,
            "supervisor_unref",
            unref_attempt,
        )
        .is_err()
    {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::UnsupportedRehydration);
    }
    let snapshot = match ledger.refresh_recovery_snapshot(snapshot) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return StartupRecoveryOutcome::Quarantined(
                StartupRecoveryFailure::UnsupportedRehydration,
            )
        }
    };
    if let Err(reason) =
        reconcile_logind_and_vt(snapshot, ledger, &logind_watch, Some(authorized_proof))
    {
        return StartupRecoveryOutcome::Quarantined(reason);
    }
    StartupRecoveryOutcome::Free
}
