use super::*;
use std::io::Write;

pub(crate) fn prepare_fixture_payload(
    provider: &SupervisorFixtureRecoveryProvider,
    identity: &crate::PayloadScopeIdentity,
    authoritative_leader_pid: u32,
    previous_vt: &PreviousVtIdentity,
) -> Result<SupervisorPreparedPayload, SupervisorRecoveryError> {
    use std::sync::atomic::Ordering;
    if provider.prepare_gate_enabled.load(Ordering::SeqCst) {
        wait_fixture_event(&provider.prepare_gate)?;
    }
    provider.counters.prepares.fetch_add(1, Ordering::SeqCst);
    Ok(SupervisorPreparedPayload {
        boundary: Box::new(SupervisorFixtureBoundary {
            identity: identity.clone(),
            object_path: format!(
                "/org/freedesktop/systemd1/unit/{}",
                identity.unit_name.replace('.', "_2e").replace('-', "_2d")
            ),
            control_group: fixture_process_cgroup(authoritative_leader_pid),
            slice: format!("/user.slice/user-{}.slice", identity.expected_uid),
            leader_pid: authoritative_leader_pid,
            mode: provider.mode,
            counters: Arc::clone(&provider.counters),
            payload_members: Arc::clone(&provider.payload_members),
            completion_event: Arc::clone(&provider.completion_event),
            released: false,
        }),
        logind: SupervisorLogindSessionIdentity {
            id: identity.logind_session_id.clone(),
            object_path: format!(
                "/org/freedesktop/login1/session/{}",
                identity
                    .logind_session_id
                    .as_str()
                    .replace('-', "_2d")
                    .replace('.', "_2e")
            ),
            uid: identity.expected_uid,
            username: "fixture-user".to_owned(),
            leader: authoritative_leader_pid,
            seat: "seat0".to_owned(),
            vt_number: 2,
            session_type: "wayland".to_owned(),
            class: "user".to_owned(),
            desktop: "niri".to_owned(),
            state: "active".to_owned(),
            scope: "session-fixture.scope".to_owned(),
        },
        vt: SupervisorVtIdentity {
            seat: "seat0".to_owned(),
            number: 2,
            previous: previous_vt.clone(),
            device_major: 4,
            device_minor: 2,
        },
        target_gid: 1000,
    })
}

pub(crate) fn fixture_event(provider: &SupervisorFixtureRecoveryProvider, value: &str) {
    if let Some(path) = &provider.operation_log {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{value}");
        }
    }
}

pub(crate) fn fixture_owner_failure(
    mode: SupervisorFixtureBoundaryMode,
) -> Option<StartupRecoveryFailure> {
    match mode {
        SupervisorFixtureBoundaryMode::SystemdOwnerBeforeKill
        | SupervisorFixtureBoundaryMode::SystemdOwnerDuringKill
        | SupervisorFixtureBoundaryMode::SystemdOwnerBeforeProof => {
            Some(StartupRecoveryFailure::SystemdOwnerChanged)
        }
        SupervisorFixtureBoundaryMode::LogindOwnerBeforeTerminate
        | SupervisorFixtureBoundaryMode::LogindOwnerDuringCleanup
        | SupervisorFixtureBoundaryMode::LogindOwnerBeforeAbsence => {
            Some(StartupRecoveryFailure::LogindOwnerChanged)
        }
        SupervisorFixtureBoundaryMode::RealSystemdOwnerChange => {
            Some(StartupRecoveryFailure::SystemdOwnerChanged)
        }
        SupervisorFixtureBoundaryMode::RealLogindOwnerChange => {
            Some(StartupRecoveryFailure::LogindOwnerChanged)
        }
        _ => None,
    }
}

pub(crate) fn reconcile_real_owner_change(
    mode: SupervisorFixtureBoundaryMode,
    provider: &SupervisorFixtureRecoveryProvider,
) -> StartupRecoveryOutcome {
    let Some(address) = std::env::var_os("NIRALIS_FIXTURE_DBUS_ADDRESS") else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::UnsupportedRehydration);
    };
    let systemd_destination = std::env::var("NIRALIS_FIXTURE_SYSTEMD_DESTINATION")
        .unwrap_or_else(|_| SYSTEMD_DESTINATION.to_owned());
    let logind_destination = std::env::var("NIRALIS_FIXTURE_LOGIND_DESTINATION")
        .unwrap_or_else(|_| LOGIND_DESTINATION.to_owned());
    let Ok((systemd, logind)) = open_recovery_owner_watches_on_address_named(
        &address.to_string_lossy(),
        &systemd_destination,
        &logind_destination,
    ) else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::UnsupportedRehydration);
    };
    let destination = if matches!(mode, SupervisorFixtureBoundaryMode::RealSystemdOwnerChange) {
        systemd_destination.as_str()
    } else {
        logind_destination.as_str()
    };
    let Some(pid) = std::env::var("NIRALIS_FIXTURE_DBUS_OWNER_PID")
        .ok()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
    else {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::UnsupportedRehydration);
    };
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
        return StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::UnsupportedRehydration);
    }
    let watch = if destination == systemd_destination {
        &systemd
    } else {
        &logind
    };
    let mut changed = false;
    for _ in 0..1024 {
        if watch.stable().is_err() {
            changed = true;
            break;
        }
        std::thread::yield_now();
    }
    if changed {
        fixture_event(provider, "owner_change:real_name_owner_changed");
        return StartupRecoveryOutcome::Quarantined(fixture_owner_failure(mode).unwrap());
    }
    StartupRecoveryOutcome::Quarantined(StartupRecoveryFailure::UnsupportedRehydration)
}

pub(crate) fn reconcile_fixture_worker(
    provider: &SupervisorFixtureRecoveryProvider,
    same_boot: &SameBootRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
) {
    let record = &same_boot.record;
    let authority = same_boot.destructive_authority();
    let identity = rehydrate_process_identity(
        record.worker_pid,
        record.worker_starttime,
        record.worker_executable,
        record.worker_cgroup.as_deref(),
    );
    if let PersistedProcessIdentity::OriginalStillAlive { pidfd } = identity {
        fixture_event(provider, "worker_alive");
        let attempt = record.sequence.saturating_add(1);
        if ledger
            .operation_intent(&record.lifecycle_id, "runtime_release", attempt)
            .is_ok()
        {
            fixture_event(provider, "worker_sigterm");
            let _ = signal_validated_worker(&authority, record, pidfd.as_raw_fd());
            let _ = wait_for_pidfd(pidfd.as_raw_fd(), 1000);
            let _ = ledger.operation_confirmed(&record.lifecycle_id, "runtime_release", attempt);
        }
    } else {
        fixture_event(provider, "worker_gone");
    }
}

pub(crate) fn reconcile_fixture_payload(
    provider: &SupervisorFixtureRecoveryProvider,
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
) -> bool {
    if matches!(
        rehydrate_process_identity(
            record.worker_pid,
            record.worker_starttime,
            record.worker_executable,
            record.worker_cgroup.as_deref(),
        ),
        PersistedProcessIdentity::OriginalStillAlive { .. }
    ) {
        fixture_event(provider, "payload_worker_still_alive");
        return false;
    }
    let Some(pid) = record.leader_pid else {
        fixture_event(provider, "payload_no_leader");
        return false;
    };
    let PersistedProcessIdentity::OriginalStillAlive { pidfd } = rehydrate_process_identity(
        pid,
        record.leader_starttime,
        record.leader_executable,
        record.control_group.as_deref(),
    ) else {
        fixture_event(provider, "payload_leader_not_alive");
        return false;
    };
    let attempt = record.sequence.saturating_add(1);
    if ledger
        .operation_intent(&record.lifecycle_id, "payload_kill", attempt)
        .is_err()
    {
        fixture_event(provider, "payload_intent_failed");
        return false;
    }
    fixture_event(
        provider,
        &format!(
            "payload_kill unit={} invocation={} object_path={} cgroup={}",
            record.payload_unit.as_deref().unwrap_or("<none>"),
            record.invocation_id.as_deref().unwrap_or("<none>"),
            record.object_path.as_deref().unwrap_or("<none>"),
            record.control_group.as_deref().unwrap_or("<none>"),
        ),
    );
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            0,
            0,
        )
    };
    if result != 0 || !wait_for_pidfd(pidfd.as_raw_fd(), 1000).unwrap_or(false) {
        fixture_event(provider, "payload_kill_failed");
        return false;
    }
    ledger
        .operation_confirmed(&record.lifecycle_id, "payload_kill", attempt)
        .is_ok()
}
