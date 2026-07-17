
impl PayloadBoundaryObserver for CgroupEventsObserver {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
    fn consume_wakeup(&mut self) -> Result<(), PayloadScopeError> {
        self.refresh()
    }
}

async fn boundary_appears_terminal(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<bool, PayloadScopeError> {
    let resolved = provider
        .resolve_by_invocation(&identity.invocation_id)
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::ResolveByInvocation, error))?;
    if resolved != pinned.object_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let properties = provider
        .read_properties(
            InvocationOperation::ReadPropertiesAfterObserver,
            &identity.invocation_id,
            &pinned.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|error| {
            map_invocation_error(InvocationOperation::ReadPropertiesAfterObserver, error)
        })?;
    validate_terminal_transition_properties(identity, pinned, control_group, &properties)?;
    Ok(terminal_unit_state(
        &properties.active_state,
        &properties.sub_state,
    ))
}

async fn request_graceful_termination(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
    worker_pid: u32,
    launcher_pid: u32,
) -> Result<(), PayloadScopeError> {
    let members = read_members(control_group)?;
    for outside_pid in [worker_pid, launcher_pid] {
        let outside = pid_cgroup(outside_pid)?;
        if outside == control_group
            || is_ancestor(control_group, &outside)
            || members.contains(&outside_pid)
        {
            return Err(PayloadScopeError::WorkerInsideBoundary);
        }
    }
    request_graceful_termination_invocation(provider, identity, pinned_unit, control_group).await
}

async fn validate_forced_termination_eligibility(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
    worker_pid: u32,
    launcher_pid: u32,
) -> Result<(), PayloadScopeError> {
    if !pinned_unit.reference_held
        || !valid_payload_cgroup(control_group, identity.expected_uid, &identity.unit_name)
    {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    let members = read_members(control_group)?;
    for outside_pid in [worker_pid, launcher_pid] {
        let outside = pid_cgroup(outside_pid)?;
        if outside == control_group
            || is_ancestor(control_group, &outside)
            || members.contains(&outside_pid)
        {
            return Err(PayloadScopeError::WorkerInsideBoundary);
        }
    }
    validate_forced_invocation_eligibility(provider, identity, pinned_unit, control_group).await
}

async fn validate_forced_invocation_eligibility(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<(), PayloadScopeError> {
    let resolved = provider
        .resolve_by_invocation(&identity.invocation_id)
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::ResolveByInvocation, error))?;
    if resolved != pinned_unit.object_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let properties = provider
        .read_properties(
            InvocationOperation::ReadPropertiesAfterRef,
            &identity.invocation_id,
            &pinned_unit.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|error| {
            map_invocation_error(InvocationOperation::ReadPropertiesAfterRef, error)
        })?;
    validate_pinned_properties(identity, pinned_unit, control_group, &properties)
}

async fn request_forced_termination(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
    worker_pid: u32,
    launcher_pid: u32,
) -> Result<(), PayloadScopeError> {
    validate_forced_termination_eligibility(
        provider,
        identity,
        pinned_unit,
        control_group,
        worker_pid,
        launcher_pid,
    )
    .await?;
    request_forced_signal_invocation(provider, identity, pinned_unit, control_group).await
}

#[cfg(test)]
async fn request_forced_termination_invocation(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<(), PayloadScopeError> {
    request_forced_signal_invocation(provider, identity, pinned_unit, control_group).await?;
    validate_forced_termination_post_kill(provider, identity, pinned_unit, control_group).await
}

async fn request_forced_signal_invocation(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<(), PayloadScopeError> {
    validate_forced_invocation_eligibility(provider, identity, pinned_unit, control_group).await?;
    info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, signal = "SIGKILL", target = "all", "requesting forced payload termination");
    provider
        .kill_pinned_unit(
            &identity.invocation_id,
            &pinned_unit.object_path,
            libc::SIGKILL,
        )
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::KillPinnedUnit, error))?;
    Ok(())
}

async fn validate_forced_termination_post_kill(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<(), PayloadScopeError> {
    // A successful Kill reply followed by disappearance is coherent: the
    // original invocation and cgroup are verified twice by the empty proof.
    match provider.resolve_by_invocation(&identity.invocation_id).await {
        Ok(path) if path == pinned_unit.object_path => {
            let properties = provider
                .read_properties(
                    InvocationOperation::ReadPropertiesAfterKill,
                    &identity.invocation_id,
                    &pinned_unit.object_path,
                    &identity.unit_name,
                )
                .await;
            match properties {
                Ok(properties) => validate_terminal_transition_properties(
                    identity,
                    pinned_unit,
                    control_group,
                    &properties,
                )?,
                Err(InvocationBackendError::NoSuchUnit | InvocationBackendError::UnknownObject) => {
                }
                Err(error) => {
                    return Err(map_invocation_error(
                        InvocationOperation::ReadPropertiesAfterKill,
                        error,
                    ))
                }
            }
        }
        Ok(_) => return Err(PayloadScopeError::UnitReplaced),
        Err(InvocationBackendError::NoSuchUnit | InvocationBackendError::UnknownObject) => {}
        Err(error) => {
            return Err(map_invocation_error(
                InvocationOperation::ReadPropertiesAfterKill,
                error,
            ))
        }
    }
    info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, "forced payload termination requested");
    Ok(())
}

async fn request_graceful_termination_invocation(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<(), PayloadScopeError> {
    if !pinned_unit.reference_held {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    let resolved = provider
        .resolve_by_invocation(&identity.invocation_id)
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::ResolveByInvocation, error))?;
    if resolved != pinned_unit.object_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let properties = provider
        .read_properties(
            InvocationOperation::ReadPropertiesAfterRef,
            &identity.invocation_id,
            &pinned_unit.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|error| {
            map_invocation_error(InvocationOperation::ReadPropertiesAfterRef, error)
        })?;
    validate_pinned_properties(identity, pinned_unit, control_group, &properties)?;
    if properties.active_state != "active" || properties.sub_state != "running" {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    provider
        .kill_pinned_unit(
            &identity.invocation_id,
            &pinned_unit.object_path,
            libc::SIGTERM,
        )
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::KillPinnedUnit, error))?;
    let properties_after = provider
        .read_properties(
            InvocationOperation::ReadPropertiesAfterKill,
            &identity.invocation_id,
            &pinned_unit.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|error| {
            map_invocation_error(InvocationOperation::ReadPropertiesAfterKill, error)
        })?;
    validate_terminal_transition_properties(
        identity,
        pinned_unit,
        control_group,
        &properties_after,
    )?;
    Ok(())
}

const MAX_CGROUP_STATE_BYTES: u64 = 4096;

enum ResolvedInvocationState {
    Present(OwnedObjectPath),
    Missing,
}

async fn resolve_invocation_for_proof(
    provider: &dyn InvocationBoundProvider,
    invocation_id: &str,
) -> Result<ResolvedInvocationState, PayloadScopeError> {
    match provider.resolve_by_invocation(invocation_id).await {
        Ok(path) => Ok(ResolvedInvocationState::Present(path)),
        Err(InvocationBackendError::NoSuchUnit | InvocationBackendError::UnknownObject) => {
            Ok(ResolvedInvocationState::Missing)
        }
        Err(error) => Err(map_invocation_error(
            InvocationOperation::ResolveByInvocation,
            error,
        )),
    }
}

async fn validate_terminal_unit(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    path: &OwnedObjectPath,
) -> Result<(), PayloadScopeError> {
    if path != &pinned.object_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let properties = provider
        .read_properties(
            InvocationOperation::ReadPropertiesDuringEmptyProof,
            &identity.invocation_id,
            path,
            &identity.unit_name,
        )
        .await
        .map_err(|error| {
            map_invocation_error(InvocationOperation::ReadPropertiesDuringEmptyProof, error)
        })?;
    validate_terminal_transition_properties(identity, pinned, control_group, &properties)?;
    if !terminal_unit_state(&properties.active_state, &properties.sub_state) {
        return Err(PayloadScopeError::UnitNotTerminal);
    }
    Ok(())
}

fn terminal_unit_state(active: &str, sub: &str) -> bool {
    matches!((active, sub), ("inactive", "dead") | ("failed", "failed"))
}
