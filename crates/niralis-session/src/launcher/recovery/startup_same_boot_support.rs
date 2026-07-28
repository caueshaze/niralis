use super::*;
use std::os::fd::AsRawFd;

const RUNTIME_RELEASE_SIGTERM_WAIT_MS: i32 = 250;
const RUNTIME_RELEASE_SIGKILL_WAIT_MS: i32 = 1_000;
const RUNTIME_RELEASE_STAGE_SIGTERM_INSUFFICIENT: u8 = 1;

/// Recovery-only signal adapter. The pidfd is produced by a successful
/// SameBoot process rehydration; primitive PIDs never reach this boundary.
pub(crate) fn signal_validated_worker(
    authority: &SameBootRecoveryAuthority,
    record: &PersistentRecoveryRecord,
    fd: i32,
) -> Result<(), ()> {
    if !authority.validates(record)
        || record.worker_starttime.is_none()
        || record.worker_executable.is_none()
    {
        return Err(());
    }
    raw_send_sigterm(fd)
}

pub(crate) fn force_validated_worker_exit(
    authority: &SameBootRecoveryAuthority,
    record: &PersistentRecoveryRecord,
    fd: i32,
) -> Result<(), ()> {
    if !authority.validates(record)
        || record.worker_starttime.is_none()
        || record.worker_executable.is_none()
    {
        return Err(());
    }
    raw_send_sigkill(fd)
}

fn raw_send_sigterm(fd: i32) -> Result<(), ()> {
    raw_send_signal(fd, libc::SIGTERM)
}

fn raw_send_sigkill(fd: i32) -> Result<(), ()> {
    raw_send_signal(fd, libc::SIGKILL)
}

fn raw_send_signal(fd: i32, signal: i32) -> Result<(), ()> {
    if unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, signal, 0, 0) } < 0 {
        Err(())
    } else {
        Ok(())
    }
}
pub(crate) fn wait_for_pidfd(fd: i32, timeout_ms: i32) -> Result<bool, ()> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    if result < 0 {
        Err(())
    } else {
        Ok(result > 0 && p.revents & libc::POLLIN != 0)
    }
}

pub(crate) fn recover_validated_runtime_release(
    authority: &SameBootRecoveryAuthority,
    record: &PersistentRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
    pidfd: OwnedFd,
) -> Result<(), StartupRecoveryFailure> {
    info!(
        lifecycle_id = %record.lifecycle_id,
        "validated worker still alive after supervisor restart"
    );
    let (attempt_id, skip_sigterm) = match record.operation_ledger.runtime_release {
        DurableOperationState::NotStarted => {
            let attempt_id = record.sequence.saturating_add(1);
            ledger
                .operation_intent(&record.lifecycle_id, "runtime_release", attempt_id)
                .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
            (attempt_id, false)
        }
        DurableOperationState::IntentPersisted { attempt_id } => (attempt_id, false),
        DurableOperationState::Indeterminate { attempt_id, .. } => (attempt_id, true),
        DurableOperationState::Confirmed { .. } | DurableOperationState::Failed { .. } => {
            return Err(StartupRecoveryFailure::WorkerIdentityIndeterminate);
        }
    };
    if !skip_sigterm {
        info!(lifecycle_id = %record.lifecycle_id, attempt_id, "runtime_release sigterm sent");
        let _ = signal_validated_worker(authority, record, pidfd.as_raw_fd());
        if wait_for_pidfd(pidfd.as_raw_fd(), RUNTIME_RELEASE_SIGTERM_WAIT_MS).unwrap_or(false) {
            info!(lifecycle_id = %record.lifecycle_id, attempt_id, "runtime_release confirmed");
            return ledger
                .operation_confirmed(&record.lifecycle_id, "runtime_release", attempt_id)
                .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration);
        }
        ledger
            .transition_with_operation(
                &record.lifecycle_id,
                "started",
                "runtime_release",
                DurableOperationState::Indeterminate {
                    attempt_id,
                    stage: RUNTIME_RELEASE_STAGE_SIGTERM_INSUFFICIENT,
                },
            )
            .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)?;
    }
    let worker = rehydrate_process_identity(
        record.worker_pid,
        record.worker_starttime,
        record.worker_executable,
        record.worker_cgroup.as_deref(),
    );
    let pidfd = match worker {
        PersistedProcessIdentity::OriginalGone => {
            info!(lifecycle_id = %record.lifecycle_id, attempt_id, "runtime_release confirmed");
            return ledger
                .operation_confirmed(&record.lifecycle_id, "runtime_release", attempt_id)
                .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration);
        }
        PersistedProcessIdentity::OriginalStillAlive { pidfd } => pidfd,
        PersistedProcessIdentity::PidReused | PersistedProcessIdentity::Indeterminate => {
            warn!(lifecycle_id = %record.lifecycle_id, attempt_id, "runtime_release quarantined");
            return Err(StartupRecoveryFailure::WorkerIdentityIndeterminate);
        }
    };
    info!(lifecycle_id = %record.lifecycle_id, attempt_id, "runtime_release escalated");
    let _ = force_validated_worker_exit(authority, record, pidfd.as_raw_fd());
    if !wait_for_pidfd(pidfd.as_raw_fd(), RUNTIME_RELEASE_SIGKILL_WAIT_MS).unwrap_or(false) {
        warn!(lifecycle_id = %record.lifecycle_id, attempt_id, "runtime_release quarantined");
        return Err(StartupRecoveryFailure::WorkerIdentityIndeterminate);
    }
    info!(lifecycle_id = %record.lifecycle_id, attempt_id, "runtime_release confirmed");
    ledger
        .operation_confirmed(&record.lifecycle_id, "runtime_release", attempt_id)
        .map_err(|_| StartupRecoveryFailure::UnsupportedRehydration)
}
pub(crate) fn wait_for_boundary_empty(
    pin: &RecoveryPinnedInvocationUnit,
    owner_watch: &OwnerWatch,
    authority: &AuthoritySnapshot,
) -> Result<(), StartupRecoveryFailure> {
    let mut observer = CgroupEventsObserver::open(pin.control_group())
        .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    let timer = MonotonicTimer::arm(EMERGENCY_BOUNDARY_TIMEOUT)
        .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    loop {
        owner_watch
            .still_authorizes(authority)
            .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
        if matches!(
            pin.boundary_state()
                .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?,
            SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent
        ) {
            return Ok(());
        }
        let mut descriptors = [
            libc::pollfd {
                fd: observer.file.as_raw_fd(),
                events: libc::POLLPRI | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: timer.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: owner_watch.event_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(descriptors.as_mut_ptr(), 3, -1) } < 0 {
            return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
        }
        if descriptors[1].revents & libc::POLLIN != 0 {
            return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
        }
        if descriptors[2].revents & libc::POLLIN != 0 {
            owner_watch
                .still_authorizes(authority)
                .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
        }
        if descriptors[0].revents & (libc::POLLPRI | libc::POLLERR) != 0 {
            observer
                .refresh()
                .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
        }
    }
}
pub(crate) fn startup_boundary_proof(
    pin: &RecoveryPinnedInvocationUnit,
    owner_watch: &OwnerWatch,
    authority: &AuthoritySnapshot,
    snapshot: &RecoveryStateSnapshot,
) -> Result<RecoveryBoundaryEmptyProof, StartupRecoveryFailure> {
    owner_watch
        .still_authorizes(authority)
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    pin.validate_owner()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    if !matches!(
        pin.boundary_state()
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?,
        SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent
    ) {
        return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
    }
    ensure_outside_boundary(pin.worker_pid(), pin.control_group())
        .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    ensure_outside_boundary(pin.launcher_pid(), pin.control_group())
        .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
    for _ in 0..2 {
        owner_watch
            .still_authorizes(authority)
            .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
        let observation = pin
            .revalidate(true)
            .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?;
        if !unit_is_terminal(&observation)
            && !matches!(
                pin.boundary_state()
                    .map_err(|_| StartupRecoveryFailure::BoundaryIdentityChanged)?,
                SupervisorBoundaryState::Absent
            )
        {
            return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
        }
    }
    owner_watch
        .still_authorizes(authority)
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    pin.validate_owner()
        .map_err(|_| StartupRecoveryFailure::SystemdOwnerChanged)?;
    if !snapshot.validates() {
        return Err(StartupRecoveryFailure::BoundaryIdentityChanged);
    }
    Ok(RecoveryBoundaryEmptyProof::from_verified_boundary(
        snapshot, pin,
    ))
}
