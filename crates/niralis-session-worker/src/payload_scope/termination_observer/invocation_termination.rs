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

