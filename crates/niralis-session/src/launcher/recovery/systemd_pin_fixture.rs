use super::super::*;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use zbus::zvariant::Value;

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1",
    gen_async = false
)]
trait SystemdManager {
    #[zbus(name = "StartTransientUnit", allow_interactive_auth)]
    fn start_transient_unit(
        &self,
        unit: &str,
        mode: &str,
        properties: Vec<(&str, Value<'_>)>,
        auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)>,
    ) -> zbus::Result<OwnedObjectPath>;

    fn get_unit(&self, unit: &str) -> zbus::Result<OwnedObjectPath>;
}

pub(super) struct SystemdScopeFixture {
    pub(super) unit: String,
    pub(super) invocation: String,
    pub(super) object_path: String,
    pub(super) control_group: String,
    slice: String,
    pub(super) leader_pid: u32,
    leader: Child,
    cleanup_needed: bool,
}

impl SystemdScopeFixture {
    pub(super) fn start() -> Result<Self, String> {
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
        let manager = SystemdManagerProxy::new(&connection)
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
        let start_result =
            manager.start_transient_unit(unit.as_str(), "fail", properties, auxiliary);
        match start_result {
            Ok(_) => {}
            Err(error) => {
                terminate_fixture_helper(&mut leader);
                return Err(format!(
                    "StartTransientUnit was rejected; run pkttyagent --process $$ in another terminal or grant this user org.freedesktop.systemd1.manage-units for the explicitly requested integration fixture: {error}"
                ));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let path: OwnedObjectPath = match manager.get_unit(unit.as_str()) {
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
                        "fixture helper or test runner has an unsafe cgroup identity".to_owned(),
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

    pub(super) fn wait_for_leader_exit(&mut self) -> Result<(), String> {
        self.leader
            .wait()
            .map(|_| ())
            .map_err(|error| format!("waiting for fixture helper failed: {error}"))
    }

    pub(super) fn disarm(&mut self) {
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
