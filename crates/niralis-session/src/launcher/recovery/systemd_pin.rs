use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SupervisorUnitObservation {
    pub(crate) object_path: String,
    pub(crate) id: String,
    pub(crate) invocation_id: String,
    pub(crate) control_group: String,
    pub(crate) slice: String,
    pub(crate) transient: bool,
    pub(crate) active_state: String,
    pub(crate) sub_state: String,
}

/// Private ownership nucleus for a systemd Unit.Ref.  No public wrapper can
/// duplicate this value, and all raw Ref/Kill/Unref calls remain here.
pub(super) struct PinnedInvocationInner {
    pub(super) connection: zbus::blocking::Connection,
    pub(super) systemd_owner: String,
    pub(super) identity: crate::PayloadScopeIdentity,
    pub(super) object_path: String,
    pub(super) control_group: String,
    pub(super) slice: String,
    pub(super) worker_pid: u32,
    pub(super) launcher_pid: u32,
    pub(super) reference_held: bool,
    emergency_kill_requested: bool,
}

pub(crate) struct LiveLifecycleBinding {
    pub(crate) identity: crate::PayloadScopeIdentity,
}

/// Pin acquired by the live lifecycle.  It is intentionally incompatible
/// with RecoveryPinnedInvocationUnit.
pub(crate) struct LivePinnedInvocationUnit {
    pub(super) inner: PinnedInvocationInner,
    pub(crate) live_binding: LiveLifecycleBinding,
}

impl fmt::Debug for LivePinnedInvocationUnit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LivePinnedInvocationUnit")
            .field("identity", &self.inner.identity)
            .field("object_path", &self.inner.object_path)
            .field("control_group", &self.inner.control_group)
            .field("slice", &self.inner.slice)
            .field("worker_pid", &self.inner.worker_pid)
            .field("launcher_pid", &self.inner.launcher_pid)
            .field("reference_held", &self.inner.reference_held)
            .finish()
    }
}

impl PinnedInvocationInner {
    pub(super) fn ref_unit(
        connection: &zbus::blocking::Connection,
        path: &OwnedObjectPath,
    ) -> Result<(), SupervisorRecoveryError> {
        unit_call(connection, path, "Ref", &())
    }

    pub(super) fn unref_unit(connection: &zbus::blocking::Connection, path: &OwnedObjectPath) {
        let _ = unit_call(connection, path, "Unref", &());
    }

    pub(super) fn acquire(
        identity: crate::PayloadScopeIdentity,
        leader_pid: u32,
        worker_pid: u32,
        launcher_pid: u32,
        leader: &SupervisorLeaderPidfd,
    ) -> Result<Self, SupervisorRecoveryError> {
        if !identity.validate() || leader.pid != leader_pid || leader.observed_dead()? {
            return Err(SupervisorRecoveryError::InvalidPayloadIdentity);
        }
        let connection = zbus::blocking::connection::Builder::system()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?
            .method_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
        let captured_systemd_owner = systemd_owner(&connection)?;
        let object_path = resolve_invocation(&connection, &identity.invocation_id)?
            .ok_or(SupervisorRecoveryError::InvalidPayloadIdentity)?;
        let first = read_unit_observation(&connection, &object_path)?;
        validate_unit_observation(&identity, &first, None)?;
        unit_call(&connection, &object_path, "Ref", &())?;
        let second_path = resolve_invocation(&connection, &identity.invocation_id)?
            .ok_or(SupervisorRecoveryError::BoundaryIdentityChanged)?;
        if second_path != object_path {
            let _ = unit_call(&connection, &object_path, "Unref", &());
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        let second = read_unit_observation(&connection, &second_path)?;
        if first != second {
            let _ = unit_call(&connection, &object_path, "Unref", &());
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        let post_ref_validation = (|| {
            validate_unit_observation(&identity, &second, None)?;
            if systemd_owner(&connection)? != captured_systemd_owner {
                return Err(SupervisorRecoveryError::BusUnavailable);
            }
            let leader_cgroup = read_pid_cgroup(leader_pid)?;
            if leader.observed_dead()? || leader_cgroup != second.control_group {
                return Err(SupervisorRecoveryError::InvalidPayloadIdentity);
            }
            ensure_outside_boundary(worker_pid, &second.control_group)?;
            ensure_outside_boundary(launcher_pid, &second.control_group)?;
            Ok(())
        })();
        if let Err(error) = post_ref_validation {
            let _ = unit_call(&connection, &object_path, "Unref", &());
            return Err(error);
        }
        info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, "supervisor live pin validated");
        Ok(Self {
            connection,
            systemd_owner: captured_systemd_owner,
            identity,
            object_path: object_path.to_string(),
            control_group: second.control_group,
            slice: second.slice,
            worker_pid,
            launcher_pid,
            reference_held: true,
            emergency_kill_requested: false,
        })
    }

    pub(super) fn from_rehydrated(
        connection: zbus::blocking::Connection,
        systemd_owner: String,
        identity: crate::PayloadScopeIdentity,
        object_path: String,
        observation: SupervisorUnitObservation,
        worker_pid: u32,
        launcher_pid: u32,
    ) -> Self {
        Self {
            connection,
            systemd_owner,
            identity,
            object_path,
            control_group: observation.control_group,
            slice: observation.slice,
            worker_pid,
            launcher_pid,
            reference_held: true,
            emergency_kill_requested: false,
        }
    }

    pub(super) fn revalidate(
        &self,
        allow_terminal_cgroup_clear: bool,
    ) -> Result<SupervisorUnitObservation, SupervisorRecoveryError> {
        self.validate_owner()?;
        let path = resolve_invocation(&self.connection, &self.identity.invocation_id)?
            .ok_or(SupervisorRecoveryError::BoundaryIdentityChanged)?;
        if path.as_str() != self.object_path {
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        let observation = read_unit_observation(&self.connection, &path)?;
        validate_unit_observation(
            &self.identity,
            &observation,
            allow_terminal_cgroup_clear.then_some(self.control_group.as_str()),
        )?;
        if observation.slice != self.slice {
            return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
        }
        ensure_outside_boundary(self.worker_pid, &self.control_group)?;
        ensure_outside_boundary(self.launcher_pid, &self.control_group)?;
        self.validate_owner()?;
        Ok(observation)
    }

    pub(super) fn validate_owner(&self) -> Result<(), SupervisorRecoveryError> {
        if systemd_owner(&self.connection)? == self.systemd_owner {
            Ok(())
        } else {
            Err(SupervisorRecoveryError::BusUnavailable)
        }
    }

    pub(super) fn boundary_state(
        &self,
    ) -> Result<SupervisorBoundaryState, SupervisorRecoveryError> {
        read_supervisor_boundary_state(&self.control_group)
    }

    pub(super) fn request_emergency_kill(&mut self) -> Result<(), SupervisorRecoveryError> {
        if self.emergency_kill_requested {
            return Err(SupervisorRecoveryError::BusDeliveryIndeterminate);
        }
        self.revalidate(false)?;
        if matches!(
            self.boundary_state()?,
            SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent
        ) {
            return Ok(());
        }
        self.emergency_kill_requested = true;
        let path = OwnedObjectPath::try_from(self.object_path.as_str())
            .map_err(|_| SupervisorRecoveryError::BoundaryIdentityChanged)?;
        unit_call(&self.connection, &path, "Kill", &("all", libc::SIGKILL)).map_err(|error| {
            match error {
                SupervisorRecoveryError::BusUnavailable => {
                    SupervisorRecoveryError::BusDeliveryIndeterminate
                }
                other => other,
            }
        })?;
        self.validate_owner()
            .map_err(|_| SupervisorRecoveryError::BusDeliveryIndeterminate)?;
        Ok(())
    }

    pub(super) fn release(&mut self) -> Result<(), SupervisorRecoveryError> {
        if !self.reference_held {
            return Ok(());
        }
        self.validate_owner()?;
        let path = OwnedObjectPath::try_from(self.object_path.as_str())
            .map_err(|_| SupervisorRecoveryError::BoundaryIdentityChanged)?;
        unit_call(&self.connection, &path, "Unref", &())
            .map_err(|_| SupervisorRecoveryError::SupervisorUnrefFailed)?;
        self.reference_held = false;
        Ok(())
    }
}

#[cfg(all(test, feature = "systemd-integration-tests"))]
#[path = "systemd_pin_integration_tests.rs"]
mod systemd_integration_tests;
