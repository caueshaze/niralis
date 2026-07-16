use std::fs;
use std::io::Read;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use futures_lite::{future, StreamExt};
use niralis_session::{LogindSessionId, PayloadScopeIdentity};
use tracing::{info, warn};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

use crate::session_child::SessionChildReport;

const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT: &str = "org.freedesktop.systemd1.Unit";
const SYSTEMD_SCOPE: &str = "org.freedesktop.systemd1.Scope";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PayloadScopeError {
    #[error("system manager bus unavailable")]
    BusUnavailable,
    #[error("transient payload scope request failed")]
    StartFailed,
    #[error("systemd payload scope job timed out")]
    TimedOut,
    #[error("systemd payload scope job failed")]
    JobFailed,
    #[error("transient payload scope identity was invalid")]
    InvalidIdentity,
    #[error("authoritative process cgroup did not match the transient unit")]
    CgroupMismatch,
    #[error("transient payload scope membership was invalid")]
    InvalidMembership,
    #[error("worker or launcher is inside the payload boundary")]
    WorkerInsideBoundary,
    #[error("pre-commit payload scope cleanup failed")]
    CleanupFailed,
}

pub trait AuthoritativePayloadScope: Send {
    fn identity(&self) -> &PayloadScopeIdentity;
    fn control_group(&self) -> &str;
    fn cleanup(self: Box<Self>, deadline: Instant) -> Result<(), PayloadScopeError>;
}

pub trait PayloadScopeManager: Send + Sync {
    fn requires_supervisor_registration(&self) -> bool {
        true
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &self,
        report: &SessionChildReport,
        authoritative_pidfd: RawFd,
        expected_uid: u32,
        logind_session_id: &LogindSessionId,
        worker_pid: u32,
        launcher_pid: u32,
        deadline: Instant,
    ) -> Result<Box<dyn AuthoritativePayloadScope>, PayloadScopeError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemdPayloadScopeManager;

struct SystemdPayloadScope {
    connection: zbus::Connection,
    identity: PayloadScopeIdentity,
    object_path: OwnedObjectPath,
    control_group: String,
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
            &self.identity.unit_name,
            &self.object_path,
            &self.control_group,
            &self.identity.invocation_id,
            deadline,
        ))
    }
}

impl PayloadScopeManager for SystemdPayloadScopeManager {
    fn prepare(
        &self,
        report: &SessionChildReport,
        authoritative_pidfd: RawFd,
        expected_uid: u32,
        logind_session_id: &LogindSessionId,
        worker_pid: u32,
        launcher_pid: u32,
        deadline: Instant,
    ) -> Result<Box<dyn AuthoritativePayloadScope>, PayloadScopeError> {
        if expected_uid == 0
            || report.child_pid != report.process_identity.pid
            || report.process_identity.sid != report.child_pid
            || report.process_identity.pgid != report.child_pid
            || authoritative_pidfd < 0
        {
            return Err(PayloadScopeError::InvalidIdentity);
        }
        async_io::block_on(prepare_scope(
            report.child_pid,
            authoritative_pidfd,
            expected_uid,
            logind_session_id,
            worker_pid,
            launcher_pid,
            deadline,
        ))
        .map(|scope| Box::new(scope) as Box<dyn AuthoritativePayloadScope>)
    }
}

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
        identity,
        object_path,
        control_group,
    })
}

async fn stop_created_unit(
    manager: &zbus::Proxy<'_>,
    unit_name: &str,
    deadline: Instant,
) -> Result<(), PayloadScopeError> {
    let mut jobs = manager
        .receive_signal_with_args("JobRemoved", &[(2, unit_name)])
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let job: OwnedObjectPath = manager
        .call("StopUnit", &(unit_name, "fail"))
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    wait_job(&mut jobs, &job, deadline)
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)
}

async fn wait_job(
    jobs: &mut zbus::proxy::SignalStream<'_>,
    expected_path: &ObjectPath<'_>,
    deadline: Instant,
) -> Result<(), PayloadScopeError> {
    let timeout = remaining(deadline)?;
    let next = jobs.next();
    let timer = async_io::Timer::after(timeout);
    futures_lite::pin!(next, timer);
    match future::race(next, async {
        timer.await;
        None
    })
    .await
    {
        Some(message) => {
            let (id, path, _unit, result): (u32, OwnedObjectPath, String, String) = message
                .body()
                .deserialize()
                .map_err(|_| PayloadScopeError::JobFailed)?;
            if id == 0 || path.as_str() != expected_path.as_str() || result != "done" {
                return Err(PayloadScopeError::JobFailed);
            }
            Ok(())
        }
        None => Err(PayloadScopeError::TimedOut),
    }
}

async fn cleanup_unit(
    connection: &zbus::Connection,
    unit_name: &str,
    object_path: &OwnedObjectPath,
    control_group: &str,
    invocation_id: &str,
    deadline: Instant,
) -> Result<(), PayloadScopeError> {
    info!(unit = %unit_name, "payload scope launch cleanup started");
    let unit = zbus::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        object_path.as_str(),
        SYSTEMD_UNIT,
    )
    .await
    .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let observed: Vec<u8> = unit
        .get_property("InvocationID")
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    if hex_id(&observed).as_deref() != Some(invocation_id)
        || !read_members(control_group)?.is_empty()
    {
        return Err(PayloadScopeError::CleanupFailed);
    }
    let manager = zbus::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_PATH,
        SYSTEMD_MANAGER,
    )
    .await
    .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let mut jobs = manager
        .receive_signal_with_args("JobRemoved", &[(2, unit_name)])
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let job: OwnedObjectPath = manager
        .call("StopUnit", &(unit_name, "fail"))
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    wait_job(&mut jobs, &job, deadline)
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    info!(unit = %unit_name, "payload scope launch cleanup completed");
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, PayloadScopeError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(PayloadScopeError::TimedOut)
}

fn random_id() -> Result<String, PayloadScopeError> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| PayloadScopeError::StartFailed)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn hex_id(bytes: &[u8]) -> Option<String> {
    (bytes.len() == 16).then(|| bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn valid_slice_name(value: &str, uid: u32) -> bool {
    value == format!("user-{uid}.slice") && uid != 0
}

fn valid_payload_cgroup(cgroup: &str, uid: u32, unit: &str) -> bool {
    cgroup == format!("/user.slice/user-{uid}.slice/{unit}")
        && unit.starts_with("niralis-payload-")
        && unit.ends_with(".scope")
}

fn is_ancestor(candidate: &str, path: &str) -> bool {
    path.strip_prefix(candidate)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn cgroup_file(cgroup: &str) -> Result<PathBuf, PayloadScopeError> {
    if !cgroup.starts_with('/') || cgroup.contains("..") {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    Ok(Path::new(CGROUP_ROOT)
        .join(cgroup.trim_start_matches('/'))
        .join("cgroup.procs"))
}

fn read_members(cgroup: &str) -> Result<Vec<u32>, PayloadScopeError> {
    let text = fs::read_to_string(cgroup_file(cgroup)?)
        .map_err(|_| PayloadScopeError::InvalidMembership)?;
    let mut members = text
        .lines()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PayloadScopeError::InvalidMembership)?;
    members.sort_unstable();
    Ok(members)
}

fn pid_cgroup(pid: u32) -> Result<String, PayloadScopeError> {
    parse_unified_cgroup(
        &fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map_err(|_| PayloadScopeError::CgroupMismatch)?,
    )
}

fn pidfd_cgroup(pidfd: RawFd) -> Result<String, PayloadScopeError> {
    type SdPidfdGetCgroup =
        unsafe extern "C" fn(libc::c_int, *mut *mut libc::c_char) -> libc::c_int;
    let library = unsafe { libloading::Library::new("libsystemd.so.0") }
        .map_err(|_| PayloadScopeError::CgroupMismatch)?;
    let function: libloading::Symbol<SdPidfdGetCgroup> =
        unsafe { library.get(b"sd_pidfd_get_cgroup\0") }
            .map_err(|_| PayloadScopeError::CgroupMismatch)?;
    let mut raw = std::ptr::null_mut();
    let result = unsafe { function(pidfd, &mut raw) };
    if result < 0 || raw.is_null() {
        return Err(PayloadScopeError::CgroupMismatch);
    }
    let value = unsafe { std::ffi::CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    unsafe { libc::free(raw.cast()) };
    Ok(value)
}

fn parse_unified_cgroup(text: &str) -> Result<String, PayloadScopeError> {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_owned)
        .ok_or(PayloadScopeError::CgroupMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_broad_or_wrong_scope_paths() {
        assert!(!valid_payload_cgroup(
            "/user.slice",
            1000,
            "niralis-payload-a.scope"
        ));
        assert!(!valid_payload_cgroup(
            "/user.slice/user-1000.slice",
            1000,
            "niralis-payload-a.scope"
        ));
        assert!(!valid_payload_cgroup(
            "/user.slice/user-1000.slice/session-3.scope",
            1000,
            "session-3.scope"
        ));
        assert!(valid_payload_cgroup(
            "/user.slice/user-1000.slice/niralis-payload-a.scope",
            1000,
            "niralis-payload-a.scope"
        ));
    }

    #[test]
    fn parses_only_unified_membership() {
        assert_eq!(
            parse_unified_cgroup("0::/user.slice/a.scope\n").unwrap(),
            "/user.slice/a.scope"
        );
        assert!(parse_unified_cgroup("2:cpu:/legacy\n").is_err());
    }
}
