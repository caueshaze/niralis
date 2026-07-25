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
