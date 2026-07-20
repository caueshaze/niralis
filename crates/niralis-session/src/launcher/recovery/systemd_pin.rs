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
mod systemd_integration_tests {
    use super::*;
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    #[ignore = "requires an explicitly authorized local systemd integration host"]
    fn real_invocation_bound_unit_kill_empties_scope() {
        let Some(scope) = SystemdScopeFixture::start() else {
            eprintln!("SKIP systemd integration preflight failed");
            return;
        };
        let _teardown = scope.teardown();
        let identity = crate::PayloadScopeIdentity {
            unit_name: scope.unit.clone(),
            invocation_id: scope.invocation.clone(),
            expected_uid: unsafe { libc::geteuid() },
            logind_session_id: crate::LogindSessionId::new("systemd-integration".to_owned())
                .expect("fixture logind id"),
        };
        let leader = SupervisorLeaderPidfd::open(scope.leader_pid).expect("fixture leader pidfd");
        let mut pin = SupervisorPinnedInvocationUnit::acquire(
            identity,
            scope.leader_pid,
            std::process::id(),
            std::process::id(),
            &leader,
        )
        .expect("production invocation-bound Ref and revalidation");
        assert_eq!(pin.object_path, scope.object_path);
        assert_eq!(pin.control_group, scope.control_group);
        pin.request_emergency_kill()
            .expect("production Unit.Kill(all, SIGKILL)");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !matches!(pin.boundary_state(), Ok(SupervisorBoundaryState::Empty)) {
            assert!(
                Instant::now() < deadline,
                "fixture boundary did not become empty"
            );
            std::thread::yield_now();
        }
        assert!(leader.observed_dead().expect("fixture leader observation"));
        assert!(std::fs::read_to_string(format!(
            "/sys/fs/cgroup{}/cgroup.procs",
            pin.control_group
        ))
        .expect("fixture cgroup procs")
        .trim()
        .is_empty());
        assert!(matches!(
            pin.request_emergency_kill(),
            Err(SupervisorRecoveryError::BusDeliveryIndeterminate)
        ));
        pin.release().expect("production Unit.Unref");
    }

    struct SystemdScopeFixture {
        unit: String,
        invocation: String,
        object_path: String,
        control_group: String,
        leader_pid: u32,
    }

    impl SystemdScopeFixture {
        fn start() -> Option<Self> {
            if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
                || !std::path::Path::new("/usr/bin/systemd-run").exists()
            {
                return None;
            }
            let uid = unsafe { libc::geteuid() };
            let token = format!("{:032x}", rand_token());
            let unit = format!("niralis-payload-{token}.scope");
            let status = Command::new("/usr/bin/systemd-run")
                .args([
                    "--scope",
                    "--no-block",
                    "--quiet",
                    &format!("--unit={unit}"),
                    &format!("--slice=user-{uid}.slice"),
                    "/usr/bin/sleep",
                    "600",
                ])
                .status()
                .ok()?;
            if !status.success() {
                return None;
            }
            let connection = zbus::blocking::connection::Builder::system()
                .ok()?
                .build()
                .ok()?;
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let manager = zbus::blocking::Proxy::new(
                    &connection,
                    SYSTEMD_DESTINATION,
                    SYSTEMD_MANAGER_PATH,
                    SYSTEMD_MANAGER_INTERFACE,
                )
                .ok()?;
                let path: OwnedObjectPath = manager.call("GetUnit", &(unit.as_str(),)).ok()?;
                let observation = read_unit_observation(&connection, &path).ok()?;
                let procs = std::fs::read_to_string(format!(
                    "/sys/fs/cgroup{}/cgroup.procs",
                    observation.control_group
                ))
                .ok()?;
                if let Some(pid) = procs.lines().next().and_then(|value| value.parse().ok()) {
                    return Some(Self {
                        unit,
                        invocation: observation.invocation_id,
                        object_path: path.to_string(),
                        control_group: observation.control_group,
                        leader_pid: pid,
                    });
                }
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::yield_now();
            }
        }

        fn teardown(&self) -> ScopeTeardown<'_> {
            ScopeTeardown(self)
        }
    }

    struct ScopeTeardown<'a>(&'a SystemdScopeFixture);
    impl Drop for ScopeTeardown<'_> {
        fn drop(&mut self) {
            let connection = match zbus::blocking::connection::Builder::system()
                .and_then(|builder| builder.build())
            {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let Ok(Some(path)) = resolve_invocation(&connection, &self.0.invocation) else {
                return;
            };
            if path.as_str() != self.0.object_path {
                return;
            }
            let Ok(observation) = read_unit_observation(&connection, &path) else {
                return;
            };
            if observation.id != self.0.unit || observation.control_group != self.0.control_group {
                return;
            }
            let _ = unit_call(&connection, &path, "Kill", &("all", libc::SIGKILL));
        }
    }

    fn rand_token() -> u128 {
        let mut bytes = [0u8; 16];
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut bytes))
            .is_ok()
        {
            u128::from_ne_bytes(bytes)
        } else {
            0
        }
    }
}
