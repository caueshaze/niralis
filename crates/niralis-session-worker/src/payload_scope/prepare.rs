
async fn prepare_scope(
    pid: u32,
    pidfd: RawFd,
    expected_uid: u32,
    logind_session_id: &LogindSessionId,
    worker_pid: u32,
    launcher_pid: u32,
    deadline: Instant,
) -> Result<SystemdPayloadScope, PayloadScopeError> {
    info!("opening system bus for transient payload scope");
    let timeout = remaining(deadline)?;
    let connection = zbus::connection::Builder::system()
        .map_err(|_| PayloadScopeError::BusUnavailable)?
        .method_timeout(timeout)
        .build()
        .await
        .map_err(|_| PayloadScopeError::BusUnavailable)?;
    let invocation_provider: std::sync::Arc<dyn InvocationBoundProvider> =
        std::sync::Arc::new(ZbusInvocationProvider::new(&connection));
    let manager = zbus::Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_PATH,
        SYSTEMD_MANAGER,
    )
    .await
    .map_err(|_| PayloadScopeError::BusUnavailable)?;

    let unit_name = format!("niralis-payload-{}.scope", random_id()?);
    let slice = format!("user-{expected_uid}.slice");
    if !valid_slice_name(&slice, expected_uid) {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    let description = format!("Niralis graphical payload for UID {expected_uid}");
    let properties = vec![
        ("Description", Value::from(description.as_str())),
        ("Slice", Value::from(slice.as_str())),
        ("PIDs", Value::from(vec![pid])),
        ("CollectMode", Value::from("inactive-or-failed")),
    ];
    let auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
    let mut jobs = manager
        .receive_signal_with_args("JobRemoved", &[(2, unit_name.as_str())])
        .await
        .map_err(|error| {
            warn!(?error, unit = %unit_name, "subscribing to the systemd payload-scope job failed");
            PayloadScopeError::StartFailed
        })?;
    info!(unit = %unit_name, pid, "transient payload scope requested");
    let job_path: OwnedObjectPath = manager
        .call(
            "StartTransientUnit",
            &(unit_name.as_str(), "fail", properties, auxiliary),
        )
        .await
        .map_err(|error| {
            warn!(?error, unit = %unit_name, pid, "StartTransientUnit rejected the payload scope");
            PayloadScopeError::StartFailed
        })?;
    if let Err(error) = wait_job(&mut jobs, &job_path, deadline).await {
        if stop_created_unit(&manager, &unit_name, deadline)
            .await
            .is_err()
        {
            return Err(PayloadScopeError::CleanupFailed);
        }
        return Err(error);
    }
    info!(unit = %unit_name, "systemd payload scope job completed");

    macro_rules! checked {
        ($expression:expr) => {
            match $expression {
                Ok(value) => value,
                Err(error) => {
                    if stop_created_unit(&manager, &unit_name, deadline)
                        .await
                        .is_err()
                    {
                        return Err(PayloadScopeError::CleanupFailed);
                    }
                    return Err(error);
                }
            }
        };
    }

    let object_path: OwnedObjectPath = checked!(manager
        .call("GetUnit", &(unit_name.as_str(),))
        .await
        .map_err(|error| {
            warn!(?error, unit = %unit_name, "resolving the transient payload scope failed");
            PayloadScopeError::InvalidIdentity
        }));
    let unit = checked!(zbus::Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        object_path.as_str(),
        SYSTEMD_UNIT
    )
    .await
    .map_err(|error| {
        warn!(?error, unit = %unit_name, object_path = %object_path, "creating the transient payload scope proxy failed");
        PayloadScopeError::InvalidIdentity
    }));
    let scope = checked!(zbus::Proxy::new(
        &connection,
        SYSTEMD_DESTINATION,
        object_path.as_str(),
        SYSTEMD_SCOPE
    )
    .await
    .map_err(|error| {
        warn!(?error, unit = %unit_name, object_path = %object_path, "creating the transient payload scope-specific proxy failed");
        PayloadScopeError::InvalidIdentity
    }));
    macro_rules! unit_property {
        ($name:literal) => {
            checked!(unit.get_property($name).await.map_err(|error| {
                warn!(?error, unit = %unit_name, property = $name, "reading transient payload scope property failed");
                PayloadScopeError::InvalidIdentity
            }))
        };
    }
    let id: String = unit_property!("Id");
    let active: String = unit_property!("ActiveState");
    let sub: String = unit_property!("SubState");
    let transient: bool = unit_property!("Transient");
    let invocation: Vec<u8> = unit_property!("InvocationID");
    macro_rules! scope_property {
        ($name:literal) => {
            checked!(scope.get_property($name).await.map_err(|error| {
                warn!(?error, unit = %unit_name, property = $name, "reading transient payload scope-specific property failed");
                PayloadScopeError::InvalidIdentity
            }))
        };
    }
    let observed_slice: String = scope_property!("Slice");
    let control_group: String = scope_property!("ControlGroup");
    let invocation_id = checked!(hex_id(&invocation).ok_or(PayloadScopeError::InvalidIdentity));
    if id != unit_name
        || active != "active"
        || sub != "running"
        || !transient
        || observed_slice != slice
        || !valid_payload_cgroup(&control_group, expected_uid, &unit_name)
    {
        warn!(
            unit = %unit_name,
            observed_id = %id,
            active_state = %active,
            sub_state = %sub,
            expected_slice = %slice,
            observed_slice = %observed_slice,
            control_group = %control_group,
            "transient payload scope properties did not match the authoritative launch identity"
        );
        checked!(Err::<(), _>(PayloadScopeError::InvalidIdentity));
    }

    let authoritative_cgroup = checked!(pidfd_cgroup(pidfd));
    if authoritative_cgroup != control_group {
        checked!(Err::<(), _>(PayloadScopeError::CgroupMismatch));
    }
    let members = checked!(read_members(&control_group));
    if members.as_slice() != [pid] {
        checked!(Err::<(), _>(PayloadScopeError::InvalidMembership));
    }
    for outside_pid in [worker_pid, launcher_pid] {
        let outside = checked!(pid_cgroup(outside_pid));
        if outside == control_group
            || is_ancestor(&control_group, &outside)
            || members.contains(&outside_pid)
        {
            checked!(Err::<(), _>(PayloadScopeError::WorkerInsideBoundary));
        }
    }
    let pinned_unit = checked!(
        pin_invocation_unit(
            invocation_provider.as_ref(),
            &unit_name,
            &invocation_id,
            &control_group,
            &slice,
        )
        .await
    );
    info!(
        pid,
        "authoritative PID attached and payload cgroup validated"
    );
    info!(
        worker_pid,
        launcher_pid, "worker and launcher confirmed outside payload scope"
    );
    let identity = PayloadScopeIdentity {
        unit_name,
        invocation_id,
        expected_uid,
        logind_session_id: logind_session_id.clone(),
    };
    Ok(SystemdPayloadScope {
        connection,
        invocation_provider,
        identity,
        pinned_unit,
        control_group,
        worker_pid,
        launcher_pid,
    })
}
