use super::*;

pub(crate) type RehydratedSupervisorPinnedInvocationUnit = SupervisorPinnedInvocationUnit;

impl SupervisorPinnedInvocationUnit {
    pub(crate) fn rehydrate(
        identity: crate::PayloadScopeIdentity,
        worker_pid: u32,
        launcher_pid: u32,
    ) -> Result<RehydratedSupervisorPinnedInvocationUnit, SupervisorRecoveryError> {
        if !identity.validate() || worker_pid == 0 || launcher_pid == 0 {
            return Err(SupervisorRecoveryError::InvalidPayloadIdentity);
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
        unit_call(&connection, &object_path, "Ref", &())?;
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
                let _ = unit_call(&connection, &object_path, "Unref", &());
                return Err(error);
            }
        };
        info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, "startup supervisor pin revalidated");
        Ok(Self {
            connection,
            systemd_owner: owner,
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
}
