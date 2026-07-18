use super::*;

pub(crate) fn wait_for_emergency_boundary(
    leader: &SupervisorLeaderPidfd,
    mut observer: Option<&mut CgroupEventsObserver>,
    pin: &SupervisorPinnedInvocationUnit,
    timeout: Duration,
) -> Result<(), SupervisorRecoveryError> {
    if leader.observed_dead()?
        && matches!(
            pin.boundary_state()?,
            SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent
        )
    {
        info!("supervisor observed authoritative leader exit");
        return Ok(());
    }
    let timer = MonotonicTimer::arm(timeout)?;
    loop {
        let mut descriptors = [
            libc::pollfd {
                fd: leader.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: observer.as_ref().map_or(-1, |value| value.file.as_raw_fd()),
                events: libc::POLLPRI | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: timer.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) };
        if result < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SupervisorRecoveryError::BoundaryObserverUnavailable);
        }
        if descriptors[2].revents & libc::POLLIN != 0 {
            return Err(SupervisorRecoveryError::BoundaryTimedOut);
        }
        if descriptors[0].revents & libc::POLLIN != 0 {
            info!("supervisor observed authoritative leader exit");
        }
        if descriptors[1].revents & (libc::POLLPRI | libc::POLLERR) != 0 {
            if let Some(value) = observer.as_deref_mut() {
                value.refresh()?;
            }
        }
        if leader.observed_dead()?
            && matches!(
                pin.boundary_state()?,
                SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent
            )
        {
            return Ok(());
        }
    }
}

pub(crate) fn prove_linux_supervisor_emergency_boundary(
    payload: &LinuxSupervisorPayloadBoundary,
    worker_exit: ExitStatus,
) -> Result<SupervisorEmergencyBoundaryProof, SupervisorRecoveryError> {
    payload.pin.validate_owner()?;
    if !payload.leader.observed_dead()? {
        return Err(SupervisorRecoveryError::LeaderStillAlive);
    }
    let first = resolve_invocation(&payload.pin.connection, &payload.pin.identity.invocation_id)?;
    if let Some(path) = &first {
        if path.as_str() != payload.pin.object_path {
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        let observation = payload.pin.revalidate(true)?;
        if !unit_is_terminal(&observation) {
            return Err(SupervisorRecoveryError::BoundaryStillPopulated);
        }
    }
    if !matches!(
        payload.pin.boundary_state()?,
        SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent
    ) {
        return Err(SupervisorRecoveryError::BoundaryStillPopulated);
    }
    ensure_outside_boundary(payload.pin.worker_pid, &payload.pin.control_group)?;
    ensure_outside_boundary(payload.pin.launcher_pid, &payload.pin.control_group)?;
    payload.pin.validate_owner()?;
    let second = resolve_invocation(&payload.pin.connection, &payload.pin.identity.invocation_id)?;
    match (&first, &second) {
        (Some(a), Some(b)) if a == b => {
            let observation = payload.pin.revalidate(true)?;
            if !unit_is_terminal(&observation) {
                return Err(SupervisorRecoveryError::BoundaryStillPopulated);
            }
        }
        (None, None) => {}
        _ => return Err(SupervisorRecoveryError::BoundaryIdentityChanged),
    }
    Ok(SupervisorEmergencyBoundaryProof {
        unit_name: payload.pin.identity.unit_name.clone(),
        invocation_id: payload.pin.identity.invocation_id.clone(),
        control_group: payload.pin.control_group.clone(),
        worker_exit: exit_status_label(worker_exit),
        leader_observed_dead: true,
        cgroup_observed_empty: true,
    })
}

pub(crate) fn exit_status_label(status: ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .map(|code| format!("exit:{code}"))
        .or_else(|| status.signal().map(|signal| format!("signal:{signal}")))
        .unwrap_or_else(|| "unknown".to_owned())
}
