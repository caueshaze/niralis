
async fn pin_invocation_unit(
    provider: &dyn InvocationBoundProvider,
    unit_name: &str,
    invocation_id: &str,
    control_group: &str,
    slice: &str,
) -> Result<PinnedInvocationUnit, PayloadScopeError> {
    let object_path = provider
        .resolve_by_invocation(invocation_id)
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::ResolveByInvocation, error))?;
    provider
        .ref_pinned_unit(invocation_id, &object_path)
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::RefPinnedUnit, error))?;
    let validation = provider
        .read_properties(
            InvocationOperation::ReadPropertiesAfterRef,
            invocation_id,
            &object_path,
            unit_name,
        )
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::ReadPropertiesAfterRef, error))
        .and_then(|properties| {
            if properties.object_path != object_path
                || properties.id != unit_name
                || properties.invocation_id != invocation_id
                || properties.control_group != control_group
                || properties.slice != slice
                || properties.active_state != "active"
                || properties.sub_state != "running"
                || !properties.transient
            {
                Err(PayloadScopeError::UnitReplaced)
            } else {
                Ok(())
            }
        });
    if let Err(error) = validation {
        let _ = provider
            .unref_pinned_unit(invocation_id, &object_path)
            .await;
        return Err(error);
    }
    info!(unit = %unit_name, invocation_id = %invocation_id, object_path = %object_path, "invocation-bound payload unit pinned");
    Ok(PinnedInvocationUnit {
        object_path,
        reference_held: true,
    })
}

async fn stop_created_unit(
    manager: &zbus::Proxy<'_>,
    unit_name: &str,
    deadline: Instant,
) -> Result<(), PayloadScopeError> {
    let mut jobs = manager
        .receive_signal_with_args("JobRemoved", &[(2, unit_name)])
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let job: OwnedObjectPath = manager
        .call("StopUnit", &(unit_name, "fail"))
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    wait_job(&mut jobs, &job, deadline)
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)
}

async fn wait_job(
    jobs: &mut zbus::proxy::SignalStream<'_>,
    expected_path: &ObjectPath<'_>,
    deadline: Instant,
) -> Result<(), PayloadScopeError> {
    let timeout = remaining(deadline)?;
    let next = jobs.next();
    let timer = async_io::Timer::after(timeout);
    futures_lite::pin!(next, timer);
    match future::race(next, async {
        timer.await;
        None
    })
    .await
    {
        Some(message) => {
            let (id, path, _unit, result): (u32, OwnedObjectPath, String, String) = message
                .body()
                .deserialize()
                .map_err(|_| PayloadScopeError::JobFailed)?;
            if id == 0 || path.as_str() != expected_path.as_str() || result != "done" {
                return Err(PayloadScopeError::JobFailed);
            }
            Ok(())
        }
        None => Err(PayloadScopeError::TimedOut),
    }
}

async fn cleanup_unit(
    connection: &zbus::Connection,
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    deadline: Instant,
    release_pin: bool,
) -> Result<(), PayloadScopeError> {
    info!(unit = %identity.unit_name, "payload scope launch cleanup started");
    match provider.read_boundary_state(&identity.invocation_id, &pinned.object_path, control_group)
    {
        Ok(CgroupEmptyState::Absent) => {
            prove_precommit_disappearance(provider, identity, pinned, control_group).await?;
            if release_pin {
                provider
                    .unref_pinned_unit(&identity.invocation_id, &pinned.object_path)
                    .await
                    .map_err(|_| PayloadScopeError::CleanupFailed)?;
            }
            info!(unit = %identity.unit_name, "payload scope disappeared boundary cleanup proved");
            return Ok(());
        }
        Ok(CgroupEmptyState::PresentEmpty) => {}
        Err(_) => return Err(PayloadScopeError::CleanupFailed),
    }
    let unit = zbus::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        pinned.object_path.as_str(),
        SYSTEMD_UNIT,
    )
    .await
    .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let observed: Vec<u8> = unit
        .get_property("InvocationID")
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    if hex_id(&observed).as_deref() != Some(identity.invocation_id.as_str())
        || !read_members(control_group)?.is_empty()
    {
        return Err(PayloadScopeError::CleanupFailed);
    }
    let manager = zbus::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_PATH,
        SYSTEMD_MANAGER,
    )
    .await
    .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let mut jobs = manager
        .receive_signal_with_args("JobRemoved", &[(2, identity.unit_name.as_str())])
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let job: OwnedObjectPath = manager
        .call("StopUnit", &(identity.unit_name.as_str(), "fail"))
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    wait_job(&mut jobs, &job, deadline)
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    if release_pin {
        unit.call::<_, _, ()>("Unref", &())
            .await
            .map_err(|_| PayloadScopeError::CleanupFailed)?;
    }
    info!(unit = %identity.unit_name, "payload scope launch cleanup completed");
    Ok(())
}

async fn prove_precommit_disappearance(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<(), PayloadScopeError> {
    if !pinned.reference_held {
        return Err(PayloadScopeError::CleanupFailed);
    }
    let first_path = provider
        .resolve_by_invocation(&identity.invocation_id)
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    if first_path != pinned.object_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let first = provider
        .read_properties(
            InvocationOperation::ReadPropertiesDuringCleanup,
            &identity.invocation_id,
            &pinned.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    validate_disappeared_boundary_properties(identity, pinned, control_group, &first)?;
    let second_path = provider
        .resolve_by_invocation(&identity.invocation_id)
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    if second_path != first_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let second = provider
        .read_properties(
            InvocationOperation::ReadPropertiesDuringCleanup,
            &identity.invocation_id,
            &pinned.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    validate_disappeared_boundary_properties(identity, pinned, control_group, &second)?;
    if first != second {
        return Err(PayloadScopeError::UnitReplaced);
    }
    Ok(())
}
