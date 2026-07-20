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
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};
    use zbus::zvariant::Value;

    #[test]
    #[ignore = "requires an explicitly authorized local systemd integration host"]
    fn real_invocation_bound_unit_kill_empties_scope() {
        let mut scope = SystemdScopeFixture::start()
            .expect("systemd integration fixture must be created with StartTransientUnit");
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
        scope
            .wait_for_leader_exit()
            .expect("fixture helper must be reaped after Unit.Kill");
        scope.disarm();
    }

    struct SystemdScopeFixture {
        unit: String,
        invocation: String,
        object_path: String,
        control_group: String,
        slice: String,
        leader_pid: u32,
        leader: Child,
        cleanup_needed: bool,
    }

    impl SystemdScopeFixture {
        fn start() -> Result<Self, String> {
            if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
                return Err("cgroup v2 is unavailable on this host".to_owned());
            }
            if !std::path::Path::new("/usr/bin/sleep").exists() {
                return Err("the fixture helper /usr/bin/sleep is unavailable".to_owned());
            }
            let uid = unsafe { libc::geteuid() };
            if uid == 0 {
                return Err(
                    "this integration test must run as the non-root fixture user; PayloadScopeIdentity intentionally rejects UID 0. Grant that user org.freedesktop.systemd1.manage-units instead of running cargo through sudo"
                        .to_owned(),
                );
            }
            let token = format!("{:032x}", rand_token()?);
            let unit = format!("niralis-payload-{token}.scope");
            let mut leader = Command::new("/usr/bin/sleep")
                .arg("600")
                .spawn()
                .map_err(|error| format!("starting fixture helper failed: {error}"))?;
            let leader_pid = leader.id();
            let connection = match zbus::blocking::connection::Builder::system()
                .map_err(|error| format!("opening the system bus failed: {error}"))
                .and_then(|builder| {
                    builder
                        .method_timeout(Duration::from_secs(30))
                        .build()
                        .map_err(|error| format!("connecting to the system bus failed: {error}"))
                }) {
                Ok(connection) => connection,
                Err(error) => {
                    terminate_fixture_helper(&mut leader);
                    return Err(error);
                }
            };
            let manager = zbus::blocking::Proxy::new(
                &connection,
                SYSTEMD_DESTINATION,
                SYSTEMD_MANAGER_PATH,
                SYSTEMD_MANAGER_INTERFACE,
            )
            .map_err(|error| format!("creating systemd Manager proxy failed: {error}"));
            let manager = match manager {
                Ok(manager) => manager,
                Err(error) => {
                    terminate_fixture_helper(&mut leader);
                    return Err(error);
                }
            };
            let slice = format!("user-{uid}.slice");
            let description = "Niralis isolated invocation-bound Unit.Kill fixture";
            let properties = vec![
                ("Description", Value::from(description)),
                ("Slice", Value::from(slice.as_str())),
                ("PIDs", Value::from(vec![leader_pid])),
                ("CollectMode", Value::from("inactive-or-failed")),
            ];
            let auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
            let start_result: Result<OwnedObjectPath, _> = manager.call(
                "StartTransientUnit",
                &(unit.as_str(), "fail", properties, auxiliary),
            );
            if let Err(error) = start_result {
                terminate_fixture_helper(&mut leader);
                return Err(format!(
                    "StartTransientUnit was rejected; grant this user org.freedesktop.systemd1.manage-units for the explicitly requested integration fixture: {error}"
                ));
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let path: OwnedObjectPath = match manager.call("GetUnit", &(unit.as_str(),)) {
                    Ok(path) => path,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::yield_now();
                        continue;
                    }
                    Err(_) => {
                        terminate_fixture_helper(&mut leader);
                        return Err("systemd did not load the transient fixture scope".to_owned());
                    }
                };
                let observation = match read_unit_observation(&connection, &path) {
                    Ok(observation) => observation,
                    Err(_) => {
                        terminate_fixture_helper(&mut leader);
                        return Err("cannot inspect the transient fixture scope".to_owned());
                    }
                };
                let procs = match std::fs::read_to_string(format!(
                    "/sys/fs/cgroup{}/cgroup.procs",
                    observation.control_group
                )) {
                    Ok(procs) => procs,
                    Err(_) => {
                        terminate_fixture_helper(&mut leader);
                        return Err("cannot read the transient fixture cgroup".to_owned());
                    }
                };
                if observation.id != unit
                    || observation.slice != slice
                    || !observation.transient
                    || observation.invocation_id.is_empty()
                {
                    terminate_fixture_helper(&mut leader);
                    return Err("transient fixture scope identity did not validate".to_owned());
                }
                if procs.lines().any(|value| value == leader_pid.to_string()) {
                    if read_pid_cgroup(leader_pid).ok().as_deref()
                        != Some(observation.control_group.as_str())
                        || ensure_outside_boundary(std::process::id(), &observation.control_group)
                            .is_err()
                    {
                        terminate_fixture_helper(&mut leader);
                        return Err(
                            "fixture helper or test runner has an unsafe cgroup identity"
                                .to_owned(),
                        );
                    }
                    return Ok(Self {
                        unit,
                        invocation: observation.invocation_id,
                        object_path: path.to_string(),
                        control_group: observation.control_group,
                        slice,
                        leader_pid,
                        leader,
                        cleanup_needed: true,
                    });
                }
                if Instant::now() >= deadline {
                    terminate_fixture_helper(&mut leader);
                    return Err("fixture helper was not attached to its transient scope".to_owned());
                }
                std::thread::yield_now();
            }
        }

        fn wait_for_leader_exit(&mut self) -> Result<(), String> {
            self.leader
                .wait()
                .map(|_| ())
                .map_err(|error| format!("waiting for fixture helper failed: {error}"))
        }

        fn disarm(&mut self) {
            self.cleanup_needed = false;
        }
    }

    impl Drop for SystemdScopeFixture {
        fn drop(&mut self) {
            if !self.cleanup_needed {
                return;
            }
            let connection = match zbus::blocking::connection::Builder::system()
                .and_then(|builder| builder.build())
            {
                Ok(connection) => connection,
                Err(_) => return,
            };
            let Ok(Some(path)) = resolve_invocation(&connection, &self.invocation) else {
                return;
            };
            if path.as_str() != self.object_path {
                return;
            }
            let Ok(observation) = read_unit_observation(&connection, &path) else {
                return;
            };
            if observation.id != self.unit
                || observation.invocation_id != self.invocation
                || observation.control_group != self.control_group
                || observation.slice != self.slice
                || !observation.transient
            {
                return;
            }
            if self.leader.try_wait().ok().flatten().is_none() {
                let _ = unit_call(&connection, &path, "Kill", &("all", libc::SIGKILL));
                let _ = self.leader.wait();
            }
            let _ = unit_call(&connection, &path, "Unref", &());
        }
    }

    fn rand_token() -> Result<u128, String> {
        let mut bytes = [0u8; 16];
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut bytes))
            .is_ok()
        {
            Ok(u128::from_ne_bytes(bytes))
        } else {
            Err("cannot obtain 128 bits of fixture entropy".to_owned())
        }
    }

    fn terminate_fixture_helper(helper: &mut Child) {
        if helper.try_wait().ok().flatten().is_none() {
            let _ = helper.kill();
            let _ = helper.wait();
        }
    }
}
