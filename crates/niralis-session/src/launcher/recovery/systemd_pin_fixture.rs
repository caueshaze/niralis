use super::super::*;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[path = "systemd_pin_fixture_cleanup.rs"]
mod systemd_pin_fixture_cleanup;
#[path = "systemd_pin_fixture_identity.rs"]
mod systemd_pin_fixture_identity;
use systemd_pin_fixture_cleanup::terminate_fixture_launcher;
use systemd_pin_fixture_identity::{
    fixture_expected_uid, fixture_helper_path, parse_ready, proc_starttime, rand_token,
    wait_for_fixture_ready,
};

pub(super) struct SystemdScopeFixture {
    pub(super) unit: String,
    pub(super) invocation: String,
    pub(super) object_path: String,
    pub(super) control_group: String,
    slice: String,
    pub(super) expected_uid: u32,
    pub(super) leader_pid: u32,
    pub(super) descendant_pid: Option<u32>,
    launcher: Child,
    _directory: tempfile::TempDir,
    cleanup_needed: bool,
}

impl SystemdScopeFixture {
    pub(super) fn start(spawn_descendant: bool) -> Result<Self, String> {
        if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            return Err("cgroup v2 is unavailable on this host".to_owned());
        }
        for required in ["/usr/bin/systemd-run"] {
            if !std::path::Path::new(required).exists() {
                return Err(format!("fixture helper {required} is unavailable"));
            }
        }
        let helper = fixture_helper_path()?;
        let helper_metadata = std::fs::metadata(&helper)
            .map_err(|_| "fixture helper metadata is unavailable".to_owned())?;
        let directory =
            tempfile::tempdir().map_err(|_| "fixture socket directory is unavailable")?;
        let ready_path = directory.path().join("ready.sock");
        let ready_listener = UnixListener::bind(&ready_path)
            .map_err(|_| "fixture helper Ready listener is unavailable")?;
        let uid = fixture_expected_uid()?;
        let unit = format!("niralis-payload-{:032x}.scope", rand_token()?);
        let slice = format!("user-{uid}.slice");
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .args([
                "--scope",
                "--quiet",
                &format!("--unit={unit}"),
                &format!("--slice={slice}"),
                helper
                    .to_str()
                    .ok_or_else(|| "fixture helper path is not UTF-8".to_owned())?,
                "--fixture-ready-socket",
                ready_path
                    .to_str()
                    .ok_or_else(|| "fixture Ready socket path is not UTF-8".to_owned())?,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if spawn_descendant {
            command.arg("--fixture-spawn-descendant");
        }
        let mut launcher = command
            .spawn()
            .map_err(|error| format!("starting transient fixture scope failed: {error}"))?;
        let ready = wait_for_fixture_ready(&ready_listener, &mut launcher)?;
        let (helper_pid, descendant_pid) = parse_ready(&ready, spawn_descendant)?;
        let helper_starttime =
            proc_starttime(helper_pid).ok_or("fixture helper starttime is unavailable")?;

        let connection = match zbus::blocking::connection::Builder::system()
            .map_err(|error| format!("opening the system bus failed: {error}"))
            .and_then(|builder| {
                builder
                    .method_timeout(Duration::from_secs(5))
                    .build()
                    .map_err(|error| format!("connecting to the system bus failed: {error}"))
            }) {
            Ok(connection) => connection,
            Err(error) => {
                terminate_fixture_launcher(&mut launcher);
                return Err(error);
            }
        };
        let manager = match zbus::blocking::Proxy::new(
            &connection,
            SYSTEMD_DESTINATION,
            SYSTEMD_MANAGER_PATH,
            SYSTEMD_MANAGER_INTERFACE,
        ) {
            Ok(manager) => manager,
            Err(error) => {
                terminate_fixture_launcher(&mut launcher);
                return Err(format!("creating systemd Manager proxy failed: {error}"));
            }
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match launcher.try_wait() {
                Ok(Some(status)) => {
                    return Err(format!(
                        "systemd-run exited before creating the transient fixture scope: {status}"
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    terminate_fixture_launcher(&mut launcher);
                    return Err(format!("observing systemd-run failed: {error}"));
                }
            }
            let path: OwnedObjectPath = match manager.call("GetUnit", &(unit.as_str(),)) {
                Ok(path) => path,
                Err(_) if Instant::now() < deadline => {
                    std::thread::yield_now();
                    continue;
                }
                Err(_) => {
                    terminate_fixture_launcher(&mut launcher);
                    return Err("systemd did not load the transient fixture scope".to_owned());
                }
            };
            let observation = match read_unit_observation(&connection, &path) {
                Ok(observation) => observation,
                Err(_) => {
                    terminate_fixture_launcher(&mut launcher);
                    return Err("cannot inspect the transient fixture scope".to_owned());
                }
            };
            if observation.id != unit
                || observation.slice != slice
                || !observation.transient
                || observation.invocation_id.is_empty()
            {
                terminate_fixture_launcher(&mut launcher);
                return Err("transient fixture scope identity did not validate".to_owned());
            }
            let Some(invocation_path) = resolve_invocation(&connection, &observation.invocation_id)
                .map_err(|error| format!("resolving fixture invocation failed: {error:?}"))?
            else {
                if Instant::now() < deadline {
                    std::thread::yield_now();
                    continue;
                }
                terminate_fixture_launcher(&mut launcher);
                return Err("systemd did not resolve the transient fixture invocation".to_owned());
            };
            let members = match std::fs::read_to_string(format!(
                "/sys/fs/cgroup{}/cgroup.procs",
                observation.control_group
            )) {
                Ok(members) => members,
                Err(_) => {
                    terminate_fixture_launcher(&mut launcher);
                    return Err("cannot read the transient fixture cgroup".to_owned());
                }
            };
            let pids: Vec<u32> = match members.lines().map(str::parse).collect::<Result<_, _>>() {
                Ok(pids) => pids,
                Err(_) => {
                    terminate_fixture_launcher(&mut launcher);
                    return Err("fixture cgroup contains an invalid PID".to_owned());
                }
            };
            if pids.len() == usize::from(spawn_descendant) + 1
                && pids.contains(&helper_pid)
                && descendant_pid.is_none_or(|pid| pids.contains(&pid))
            {
                if read_pid_cgroup(helper_pid).ok().as_deref()
                    != Some(observation.control_group.as_str())
                    || descendant_pid.is_some_and(|pid| {
                        read_pid_cgroup(pid).ok().as_deref()
                            != Some(observation.control_group.as_str())
                    })
                    || proc_starttime(helper_pid) != Some(helper_starttime)
                    || !matches!(
                        std::fs::metadata(format!("/proc/{helper_pid}/exe")).map(|metadata| {
                            metadata.dev() == helper_metadata.dev()
                                && metadata.ino() == helper_metadata.ino()
                        }),
                        Ok(true)
                    )
                    || ensure_outside_boundary(std::process::id(), &observation.control_group)
                        .is_err()
                    || (launcher.id() != helper_pid
                        && ensure_outside_boundary(launcher.id(), &observation.control_group)
                            .is_err())
                {
                    terminate_fixture_launcher(&mut launcher);
                    return Err(
                        "fixture helper or test runner has an unsafe cgroup identity".to_owned(),
                    );
                }
                return Ok(Self {
                    unit,
                    invocation: observation.invocation_id,
                    object_path: invocation_path.to_string(),
                    control_group: observation.control_group,
                    slice,
                    expected_uid: uid,
                    leader_pid: helper_pid,
                    descendant_pid,
                    launcher,
                    _directory: directory,
                    cleanup_needed: true,
                });
            }
            if Instant::now() >= deadline {
                terminate_fixture_launcher(&mut launcher);
                return Err("fixture scope did not contain exactly its dedicated helper".to_owned());
            }
            std::thread::yield_now();
        }
    }

    pub(super) fn disarm(&mut self) {
        self.cleanup_needed = false;
    }

    pub(super) fn wait_for_launcher_exit(&mut self) -> Result<(), String> {
        self.launcher
            .wait()
            .map(|_| ())
            .map_err(|error| format!("waiting for fixture launcher failed: {error}"))
    }
}
