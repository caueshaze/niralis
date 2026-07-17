
fn validate_terminal_transition_properties(
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    properties: &InvocationUnitProperties,
) -> Result<(), PayloadScopeError> {
    validate_pinned_properties_with_control_group(
        identity,
        pinned,
        control_group,
        properties,
        ControlGroupPropertyMode::AllowClearedWhenTerminal,
    )
}

#[derive(Clone, Copy)]
enum ControlGroupPropertyMode {
    Exact,
    AllowClearedWhenTerminal,
}

fn validate_pinned_properties_with_control_group(
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    properties: &InvocationUnitProperties,
    control_group_mode: ControlGroupPropertyMode,
) -> Result<(), PayloadScopeError> {
    if !pinned.reference_held || properties.object_path != pinned.object_path {
        warn!(
            expected_invocation_id = %identity.invocation_id,
            observed_invocation_id = %properties.invocation_id,
            expected_object_path = %pinned.object_path,
            observed_object_path = %properties.object_path,
            "pinned unit identity changed"
        );
        return Err(PayloadScopeError::UnitReplaced);
    }
    if properties.invocation_id != identity.invocation_id {
        warn!(
            expected_invocation_id = %identity.invocation_id,
            observed_invocation_id = %properties.invocation_id,
            "pinned unit identity changed"
        );
        return Err(PayloadScopeError::UnitReplaced);
    }
    // systemd can clear Scope.ControlGroup after removing the cgroup while a
    // Ref-held, terminal Unit object remains addressable by InvocationID. This
    // representation is accepted only after the unit is terminal; empty proof
    // still reads the original cgroup path and revalidates the invocation.
    let control_group_matches = properties.control_group == control_group
        || (matches!(
            control_group_mode,
            ControlGroupPropertyMode::AllowClearedWhenTerminal
        ) && properties.control_group.is_empty()
            && terminal_unit_state(&properties.active_state, &properties.sub_state));
    if properties.id != identity.unit_name
        || !control_group_matches
        || properties.slice != format!("user-{}.slice", identity.expected_uid)
        || !properties.transient
        || !valid_payload_cgroup(control_group, identity.expected_uid, &identity.unit_name)
    {
        warn!(
            expected_invocation_id = %identity.invocation_id,
            observed_invocation_id = %properties.invocation_id,
            expected_unit_name = %identity.unit_name,
            observed_unit_name = %properties.id,
            expected_control_group = %control_group,
            observed_control_group = %properties.control_group,
            expected_slice = %format!("user-{}.slice", identity.expected_uid),
            observed_slice = %properties.slice,
            observed_transient = properties.transient,
            observed_active_state = %properties.active_state,
            observed_sub_state = %properties.sub_state,
            "pinned unit identity changed"
        );
        return Err(PayloadScopeError::UnitReplaced);
    }
    Ok(())
}

impl AuthoritativePayloadScope for SystemdPayloadScope {
    fn identity(&self) -> &PayloadScopeIdentity {
        &self.identity
    }
    fn control_group(&self) -> &str {
        &self.control_group
    }

    fn cleanup(self: Box<Self>, deadline: Instant) -> Result<(), PayloadScopeError> {
        async_io::block_on(cleanup_unit(
            &self.connection,
            self.invocation_provider.as_ref(),
            &self.identity,
            &self.pinned_unit,
            &self.control_group,
            deadline,
            true,
        ))
    }

    fn cleanup_preserving_pin(&mut self, deadline: Instant) -> Result<(), PayloadScopeError> {
        async_io::block_on(cleanup_unit(
            &self.connection,
            self.invocation_provider.as_ref(),
            &self.identity,
            &self.pinned_unit,
            &self.control_group,
            deadline,
            false,
        ))
    }

    fn request_graceful_termination(&self) -> Result<(), PayloadScopeError> {
        async_io::block_on(request_graceful_termination(
            self.invocation_provider.as_ref(),
            &self.identity,
            &self.pinned_unit,
            &self.control_group,
            self.worker_pid,
            self.launcher_pid,
        ))
    }
    fn validate_forced_termination_eligibility(&self) -> Result<(), PayloadScopeError> {
        async_io::block_on(validate_forced_termination_eligibility(
            self.invocation_provider.as_ref(),
            &self.identity,
            &self.pinned_unit,
            &self.control_group,
            self.worker_pid,
            self.launcher_pid,
        ))
    }
    fn request_forced_termination(&self) -> Result<(), PayloadScopeError> {
        async_io::block_on(request_forced_termination(
            self.invocation_provider.as_ref(),
            &self.identity,
            &self.pinned_unit,
            &self.control_group,
            self.worker_pid,
            self.launcher_pid,
        ))
    }
    fn validate_forced_termination_post_kill(&self) -> Result<(), PayloadScopeError> {
        async_io::block_on(validate_forced_termination_post_kill(
            self.invocation_provider.as_ref(),
            &self.identity,
            &self.pinned_unit,
            &self.control_group,
        ))
    }
    fn boundary_appears_terminal(&self) -> Result<bool, PayloadScopeError> {
        async_io::block_on(boundary_appears_terminal(
            self.invocation_provider.as_ref(),
            &self.identity,
            &self.pinned_unit,
            &self.control_group,
        ))
    }
    fn create_boundary_observer(
        &self,
    ) -> Result<Box<dyn PayloadBoundaryObserver>, PayloadScopeError> {
        self.invocation_provider
            .create_boundary_observer(
                &self.identity.invocation_id,
                &self.pinned_unit.object_path,
                &self.control_group,
            )
            .map_err(|error| {
                map_invocation_error(InvocationOperation::CreateBoundaryObserver, error)
            })
    }
    fn prove_empty_boundary(
        &self,
        leader_exit: &crate::termination::LeaderExit,
    ) -> Result<crate::termination::BoundaryEmptyProof, PayloadScopeError> {
        async_io::block_on(prove_empty_boundary(
            self.invocation_provider.as_ref(),
            &self.identity,
            &self.pinned_unit,
            &self.control_group,
            self.worker_pid,
            self.launcher_pid,
            leader_exit,
        ))
    }
    fn release_pin(&mut self) -> Result<(), PayloadScopeError> {
        async_io::block_on(release_pin(
            self.invocation_provider.as_ref(),
            &self.identity,
            &mut self.pinned_unit,
        ))
    }
}

struct CgroupEventsObserver {
    file: std::fs::File,
}

impl CgroupEventsObserver {
    fn open(control_group: &str) -> Result<Self, PayloadScopeError> {
        let path = cgroup_file_named(control_group, "cgroup.events")?;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| PayloadScopeError::ObserverFailed)?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(PayloadScopeError::ObserverFailed);
        }
        let mut observer = Self {
            file: unsafe { std::fs::File::from_raw_fd(fd) },
        };
        observer.refresh()?;
        Ok(observer)
    }

    fn refresh(&mut self) -> Result<(), PayloadScopeError> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| PayloadScopeError::ObserverFailed)?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(MAX_CGROUP_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PayloadScopeError::ObserverFailed)?;
        if bytes.len() as u64 > MAX_CGROUP_STATE_BYTES {
            return Err(PayloadScopeError::ObserverFailed);
        }
        let value = std::str::from_utf8(&bytes).map_err(|_| PayloadScopeError::ObserverFailed)?;
        parse_populated(value)
            .map(|_| ())
            .map_err(|_| PayloadScopeError::ObserverFailed)
    }
}
