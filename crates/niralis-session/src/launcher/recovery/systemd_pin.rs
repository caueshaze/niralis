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

pub(crate) struct SupervisorPinnedInvocationUnit {
    pub(crate) connection: zbus::blocking::Connection,
    pub(crate) systemd_owner: String,
    pub(crate) identity: crate::PayloadScopeIdentity,
    pub(crate) object_path: String,
    pub(crate) control_group: String,
    pub(crate) slice: String,
    pub(crate) worker_pid: u32,
    pub(crate) launcher_pid: u32,
    pub(crate) reference_held: bool,
    pub(crate) emergency_kill_requested: bool,
}

impl fmt::Debug for SupervisorPinnedInvocationUnit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisorPinnedInvocationUnit")
            .field("identity", &self.identity)
            .field("object_path", &self.object_path)
            .field("control_group", &self.control_group)
            .field("slice", &self.slice)
            .field("worker_pid", &self.worker_pid)
            .field("launcher_pid", &self.launcher_pid)
            .field("reference_held", &self.reference_held)
            .field("emergency_kill_requested", &self.emergency_kill_requested)
            .finish()
    }
}

impl SupervisorPinnedInvocationUnit {
    pub(crate) fn acquire(
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
        info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, "supervisor recovery pin validated");
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

    pub(crate) fn revalidate(
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

    pub(crate) fn validate_owner(&self) -> Result<(), SupervisorRecoveryError> {
        if systemd_owner(&self.connection)? == self.systemd_owner {
            Ok(())
        } else {
            Err(SupervisorRecoveryError::BusUnavailable)
        }
    }

    pub(crate) fn boundary_state(
        &self,
    ) -> Result<SupervisorBoundaryState, SupervisorRecoveryError> {
        read_supervisor_boundary_state(&self.control_group)
    }

    pub(crate) fn request_emergency_kill(&mut self) -> Result<(), SupervisorRecoveryError> {
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
        info!(
            signal = "SIGKILL",
            target = "all",
            "requesting emergency supervisor payload termination"
        );
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
        info!("emergency payload termination requested");
        Ok(())
    }

    pub(crate) fn release(&mut self) -> Result<(), SupervisorRecoveryError> {
        if !self.reference_held {
            return Ok(());
        }
        info!("releasing supervisor-owned systemd unit reference");
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
