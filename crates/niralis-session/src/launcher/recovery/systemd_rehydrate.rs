use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryInvocationBinding {
    boot_id: BootIdentity,
    record_id: String,
    lifecycle_id: String,
    record_sequence: u64,
    invocation_id: String,
    control_group: String,
    owner_generation: u64,
}

/// Recovery-only wrapper. The inner Unit.Ref owner cannot be converted into a
/// live pin and all effectful methods validate this binding first.
pub(crate) struct RecoveryPinnedInvocationUnit {
    pub(super) inner: PinnedInvocationInner,
    binding: RecoveryInvocationBinding,
}

impl RecoveryPinnedInvocationUnit {
    pub(crate) fn control_group(&self) -> &str {
        &self.inner.control_group
    }
    pub(crate) fn invocation_id(&self) -> &str {
        &self.binding.invocation_id
    }
    pub(crate) fn worker_pid(&self) -> u32 {
        self.inner.worker_pid
    }
    pub(crate) fn launcher_pid(&self) -> u32 {
        self.inner.launcher_pid
    }
    pub(crate) fn owner_generation(&self) -> u64 {
        self.binding.owner_generation
    }
    pub(crate) fn revalidate(
        &self,
        terminal: bool,
    ) -> Result<SupervisorUnitObservation, SupervisorRecoveryError> {
        self.inner.revalidate(terminal)
    }
    pub(crate) fn validate_owner(&self) -> Result<(), SupervisorRecoveryError> {
        self.inner.validate_owner()
    }
    pub(crate) fn boundary_state(
        &self,
    ) -> Result<SupervisorBoundaryState, SupervisorRecoveryError> {
        self.inner.boundary_state()
    }

    pub(crate) fn rebind(
        &mut self,
        authority: &SameBootRecoveryAuthority,
        record: &PersistentRecoveryRecord,
    ) -> Result<(), SupervisorRecoveryError> {
        if !authority.validates(record)
            || self.binding.record_id != record.lifecycle_id
            || self.binding.lifecycle_id != record.lifecycle_id
            || self.binding.invocation_id != record.invocation_id.clone().unwrap_or_default()
            || self.binding.control_group != record.control_group.clone().unwrap_or_default()
        {
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        self.binding.record_sequence = record.sequence;
        Ok(())
    }

    pub(crate) fn request_recovery_emergency_kill(
        &mut self,
        authority: &SameBootRecoveryAuthority,
        record: &PersistentRecoveryRecord,
        permit: RecoveryOperationPermit<PayloadKillOperation>,
    ) -> Result<(), SupervisorRecoveryError> {
        self.validate_binding(authority, record, &permit)?;
        self.inner.request_emergency_kill()
    }

    pub(crate) fn release_recovery(
        &mut self,
        authority: &SameBootRecoveryAuthority,
        record: &PersistentRecoveryRecord,
        permit: RecoveryOperationPermit<SupervisorUnrefOperation>,
        proof: &AuthorizedRecoveryBoundaryProof,
    ) -> Result<(), SupervisorRecoveryError> {
        self.validate_binding(authority, record, &permit)?;
        if !proof.matches_pin(record, self) {
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        self.inner.release()
    }

    fn validate_binding<K>(
        &self,
        authority: &SameBootRecoveryAuthority,
        record: &PersistentRecoveryRecord,
        permit: &RecoveryOperationPermit<K>,
    ) -> Result<(), SupervisorRecoveryError> {
        if !authority.validates(record)
            || self.binding.boot_id != *authority.boot_id()
            || self.binding.record_id != record.lifecycle_id
            || self.binding.lifecycle_id != record.lifecycle_id
            || self.binding.record_sequence != record.sequence
            || self.binding.invocation_id != record.invocation_id.clone().unwrap_or_default()
            || self.binding.control_group != record.control_group.clone().unwrap_or_default()
            || !permit.matches(record, authority.boot_id(), permit.attempt_id())
        {
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        self.inner.validate_owner()
    }
}

impl RecoveryPinnedInvocationUnit {
    pub(crate) fn rehydrate(
        identity: crate::PayloadScopeIdentity,
        worker_pid: u32,
        launcher_pid: u32,
        authority: &SameBootRecoveryAuthority,
        record: &PersistentRecoveryRecord,
    ) -> Result<Self, SupervisorRecoveryError> {
        if !identity.validate()
            || worker_pid == 0
            || launcher_pid == 0
            || !authority.validates(record)
        {
            return Err(SupervisorRecoveryError::InvalidPayloadIdentity);
        }
        if record.invocation_id.as_deref() != Some(identity.invocation_id.as_str())
            || record.control_group.as_deref().is_none()
        {
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        let connection = zbus::blocking::connection::Builder::system()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?
            .method_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
        let owner = systemd_owner(&connection)?;
        let object_path = resolve_invocation(&connection, &identity.invocation_id)?
            .ok_or(SupervisorRecoveryError::BoundaryIdentityChanged)?;
        let first = read_unit_observation(&connection, &object_path)?;
        validate_unit_observation(&identity, &first, None)?;
        PinnedInvocationInner::ref_unit(&connection, &object_path)?;
        let valid = (|| {
            let second_path = resolve_invocation(&connection, &identity.invocation_id)?
                .ok_or(SupervisorRecoveryError::BoundaryIdentityChanged)?;
            if second_path != object_path {
                return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
            }
            let second = read_unit_observation(&connection, &second_path)?;
            validate_unit_observation(&identity, &second, None)?;
            ensure_outside_boundary(worker_pid, &second.control_group)?;
            ensure_outside_boundary(launcher_pid, &second.control_group)?;
            if first != second || systemd_owner(&connection)? != owner {
                return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
            }
            Ok(second)
        })();
        let second = match valid {
            Ok(value) => value,
            Err(error) => {
                PinnedInvocationInner::unref_unit(&connection, &object_path);
                return Err(error);
            }
        };
        let binding = RecoveryInvocationBinding {
            boot_id: authority.boot_id().clone(),
            record_id: record.lifecycle_id.clone(),
            lifecycle_id: record.lifecycle_id.clone(),
            record_sequence: record.sequence,
            invocation_id: identity.invocation_id.clone(),
            control_group: second.control_group.clone(),
            owner_generation: 0,
        };
        info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, "startup supervisor recovery pin revalidated");
        Ok(Self {
            inner: PinnedInvocationInner::from_rehydrated(
                connection,
                owner,
                identity,
                object_path.to_string(),
                second,
                worker_pid,
                launcher_pid,
            ),
            binding,
        })
    }
}
