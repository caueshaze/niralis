use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
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
    #[error("payload boundary event observer failed")]
    ObserverFailed,
    #[error("payload scope unit was replaced")]
    UnitReplaced,
    #[error("payload boundary is not empty")]
    BoundaryNotEmpty,
    #[error("payload scope unit is not terminal")]
    UnitNotTerminal,
    #[error("pinned payload scope reference release failed")]
    UnrefFailed,
    #[error("expected payload invocation is no longer available")]
    InvocationUnavailable,
    #[error("system manager transport failed during an invocation-bound operation")]
    TransportFailure,
    #[error("system manager service owner changed during an invocation-bound operation")]
    ServiceOwnerChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvocationOperation {
    ResolveByInvocation,
    RefPinnedUnit,
    ReadPropertiesAfterRef,
    KillPinnedUnit,
    ReadPropertiesAfterKill,
    CreateBoundaryObserver,
    ReadPropertiesAfterObserver,
    ReadBoundaryState,
    ReadPropertiesDuringEmptyProof,
    ReadPropertiesDuringCleanup,
    UnrefPinnedUnit,
}

impl InvocationOperation {
    fn stage(self) -> &'static str {
        match self {
            Self::ResolveByInvocation => "resolve",
            Self::RefPinnedUnit => "ref",
            Self::ReadPropertiesAfterRef => "post_ref",
            Self::KillPinnedUnit => "kill",
            Self::ReadPropertiesAfterKill => "post_kill",
            Self::CreateBoundaryObserver | Self::ReadPropertiesAfterObserver => "observe",
            Self::ReadBoundaryState | Self::ReadPropertiesDuringEmptyProof => "proof",
            Self::ReadPropertiesDuringCleanup => "cleanup",
            Self::UnrefPinnedUnit => "unref",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InvocationUnitProperties {
    object_path: OwnedObjectPath,
    id: String,
    invocation_id: String,
    control_group: String,
    slice: String,
    transient: bool,
    active_state: String,
    sub_state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvocationBackendError {
    NoSuchUnit,
    UnknownObject,
    BusDisconnected,
    ServiceOwnerChanged,
    Transport,
    BoundaryNotEmpty,
    CgroupAbsent,
    CgroupIo,
}

type InvocationFuture<'a, T> =
    Pin<Box<dyn std::future::Future<Output = Result<T, InvocationBackendError>> + 'a>>;

/// The Running lifecycle can express operations only against an expected
/// InvocationID and its pinned object path. There is deliberately no
/// name-based destructive method in this interface.
trait InvocationBoundProvider: Send + Sync {
    fn resolve_by_invocation<'a>(
        &'a self,
        expected_invocation_id: &'a str,
    ) -> InvocationFuture<'a, OwnedObjectPath>;
    fn ref_pinned_unit<'a>(
        &'a self,
        expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
    ) -> InvocationFuture<'a, ()>;
    fn read_properties<'a>(
        &'a self,
        operation: InvocationOperation,
        expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
        expected_unit_name: &'a str,
    ) -> InvocationFuture<'a, InvocationUnitProperties>;
    fn kill_pinned_unit<'a>(
        &'a self,
        expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
        signal: libc::c_int,
    ) -> InvocationFuture<'a, ()>;
    fn create_boundary_observer(
        &self,
        expected_invocation_id: &str,
        expected_object_path: &OwnedObjectPath,
        control_group: &str,
    ) -> Result<Box<dyn PayloadBoundaryObserver>, InvocationBackendError>;
    fn read_boundary_state(
        &self,
        expected_invocation_id: &str,
        expected_object_path: &OwnedObjectPath,
        control_group: &str,
    ) -> Result<CgroupEmptyState, InvocationBackendError>;
    fn unref_pinned_unit<'a>(
        &'a self,
        expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
    ) -> InvocationFuture<'a, ()>;
}

pub trait PayloadBoundaryObserver: Send {
    fn as_raw_fd(&self) -> RawFd;
    fn poll_events(&self) -> libc::c_short {
        libc::POLLPRI | libc::POLLERR
    }
    fn consume_wakeup(&mut self) -> Result<(), PayloadScopeError>;
}

pub trait AuthoritativePayloadScope: Send {
    fn identity(&self) -> &PayloadScopeIdentity;
    fn control_group(&self) -> &str;
    fn cleanup(self: Box<Self>, deadline: Instant) -> Result<(), PayloadScopeError>;
    fn cleanup_preserving_pin(&mut self, _deadline: Instant) -> Result<(), PayloadScopeError> {
        Err(PayloadScopeError::CleanupFailed)
    }
    fn request_graceful_termination(&self) -> Result<(), PayloadScopeError> {
        Err(PayloadScopeError::StartFailed)
    }
    fn boundary_appears_terminal(&self) -> Result<bool, PayloadScopeError> {
        Ok(false)
    }
    fn create_boundary_observer(
        &self,
    ) -> Result<Box<dyn PayloadBoundaryObserver>, PayloadScopeError> {
        Err(PayloadScopeError::ObserverFailed)
    }
    fn prove_empty_boundary(
        &self,
        _leader_exit: &crate::termination::LeaderExit,
    ) -> Result<crate::termination::BoundaryEmptyProof, PayloadScopeError> {
        Err(PayloadScopeError::BoundaryNotEmpty)
    }
    fn release_pin(&mut self) -> Result<(), PayloadScopeError> {
        Err(PayloadScopeError::UnrefFailed)
    }
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
    invocation_provider: std::sync::Arc<dyn InvocationBoundProvider>,
    identity: PayloadScopeIdentity,
    pinned_unit: PinnedInvocationUnit,
    control_group: String,
    worker_pid: u32,
    launcher_pid: u32,
}

#[derive(Debug)]
struct PinnedInvocationUnit {
    object_path: OwnedObjectPath,
    reference_held: bool,
}

#[derive(Clone)]
struct ZbusInvocationProvider {
    connection: zbus::Connection,
}

impl ZbusInvocationProvider {
    fn new(connection: &zbus::Connection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }
}

fn classify_zbus_error(error: zbus::Error) -> InvocationBackendError {
    match error {
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
        {
            InvocationBackendError::NoSuchUnit
        }
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.UnknownObject" =>
        {
            InvocationBackendError::UnknownObject
        }
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.NameHasNoOwner" =>
        {
            InvocationBackendError::ServiceOwnerChanged
        }
        zbus::Error::MethodError(name, _, _)
            if matches!(
                name.as_str(),
                "org.freedesktop.DBus.Error.Disconnected" | "org.freedesktop.DBus.Error.NoReply"
            ) =>
        {
            InvocationBackendError::BusDisconnected
        }
        zbus::Error::InputOutput(_) => InvocationBackendError::BusDisconnected,
        zbus::Error::FDO(error)
            if matches!(error.as_ref(), zbus::fdo::Error::NameHasNoOwner(_)) =>
        {
            InvocationBackendError::ServiceOwnerChanged
        }
        zbus::Error::FDO(error)
            if matches!(
                error.as_ref(),
                zbus::fdo::Error::Disconnected(_) | zbus::fdo::Error::NoReply(_)
            ) =>
        {
            InvocationBackendError::BusDisconnected
        }
        _ => InvocationBackendError::Transport,
    }
}

impl InvocationBoundProvider for ZbusInvocationProvider {
    fn resolve_by_invocation<'a>(
        &'a self,
        expected_invocation_id: &'a str,
    ) -> InvocationFuture<'a, OwnedObjectPath> {
        Box::pin(async move {
            let manager = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                SYSTEMD_PATH,
                SYSTEMD_MANAGER,
            )
            .await
            .map_err(classify_zbus_error)?;
            let bytes =
                parse_hex_id(expected_invocation_id).ok_or(InvocationBackendError::Transport)?;
            manager
                .call("GetUnitByInvocationID", &(bytes,))
                .await
                .map_err(classify_zbus_error)
        })
    }

    fn ref_pinned_unit<'a>(
        &'a self,
        _expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
    ) -> InvocationFuture<'a, ()> {
        Box::pin(async move {
            let unit = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_UNIT,
            )
            .await
            .map_err(classify_zbus_error)?;
            unit.call::<_, _, ()>("Ref", &())
                .await
                .map_err(classify_zbus_error)
        })
    }

    fn read_properties<'a>(
        &'a self,
        _operation: InvocationOperation,
        _expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
        _expected_unit_name: &'a str,
    ) -> InvocationFuture<'a, InvocationUnitProperties> {
        Box::pin(async move {
            let unit = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_UNIT,
            )
            .await
            .map_err(classify_zbus_error)?;
            let scope = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_SCOPE,
            )
            .await
            .map_err(classify_zbus_error)?;
            let invocation: Vec<u8> = unit
                .get_property("InvocationID")
                .await
                .map_err(classify_zbus_error)?;
            Ok(InvocationUnitProperties {
                object_path: expected_object_path.clone(),
                id: unit.get_property("Id").await.map_err(classify_zbus_error)?,
                invocation_id: hex_id(&invocation).ok_or(InvocationBackendError::Transport)?,
                control_group: scope
                    .get_property("ControlGroup")
                    .await
                    .map_err(classify_zbus_error)?,
                slice: scope
                    .get_property("Slice")
                    .await
                    .map_err(classify_zbus_error)?,
                transient: unit
                    .get_property("Transient")
                    .await
                    .map_err(classify_zbus_error)?,
                active_state: unit
                    .get_property("ActiveState")
                    .await
                    .map_err(classify_zbus_error)?,
                sub_state: unit
                    .get_property("SubState")
                    .await
                    .map_err(classify_zbus_error)?,
            })
        })
    }

    fn kill_pinned_unit<'a>(
        &'a self,
        _expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
        signal: libc::c_int,
    ) -> InvocationFuture<'a, ()> {
        Box::pin(async move {
            let unit = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_UNIT,
            )
            .await
            .map_err(classify_zbus_error)?;
            unit.call::<_, _, ()>("Kill", &("all", signal))
                .await
                .map_err(classify_zbus_error)
        })
    }

    fn create_boundary_observer(
        &self,
        _expected_invocation_id: &str,
        _expected_object_path: &OwnedObjectPath,
        control_group: &str,
    ) -> Result<Box<dyn PayloadBoundaryObserver>, InvocationBackendError> {
        CgroupEventsObserver::open(control_group)
            .map(|observer| Box::new(observer) as Box<dyn PayloadBoundaryObserver>)
            .map_err(|_| InvocationBackendError::Transport)
    }

    fn read_boundary_state(
        &self,
        _expected_invocation_id: &str,
        _expected_object_path: &OwnedObjectPath,
        control_group: &str,
    ) -> Result<CgroupEmptyState, InvocationBackendError> {
        read_cgroup_empty_state(control_group).map_err(|error| match error {
            PayloadScopeError::BoundaryNotEmpty => InvocationBackendError::BoundaryNotEmpty,
            PayloadScopeError::InvalidIdentity => InvocationBackendError::CgroupAbsent,
            _ => InvocationBackendError::CgroupIo,
        })
    }

    fn unref_pinned_unit<'a>(
        &'a self,
        _expected_invocation_id: &'a str,
        expected_object_path: &'a OwnedObjectPath,
    ) -> InvocationFuture<'a, ()> {
        Box::pin(async move {
            let unit = zbus::Proxy::new(
                &self.connection,
                SYSTEMD_DESTINATION,
                expected_object_path.as_str(),
                SYSTEMD_UNIT,
            )
            .await
            .map_err(classify_zbus_error)?;
            unit.call::<_, _, ()>("Unref", &())
                .await
                .map_err(classify_zbus_error)
        })
    }
}

fn map_invocation_error(
    operation: InvocationOperation,
    error: InvocationBackendError,
) -> PayloadScopeError {
    let mapped = match error {
        InvocationBackendError::NoSuchUnit | InvocationBackendError::UnknownObject => {
            PayloadScopeError::InvocationUnavailable
        }
        InvocationBackendError::BusDisconnected => PayloadScopeError::BusUnavailable,
        InvocationBackendError::ServiceOwnerChanged => PayloadScopeError::ServiceOwnerChanged,
        InvocationBackendError::Transport => PayloadScopeError::TransportFailure,
        InvocationBackendError::BoundaryNotEmpty => PayloadScopeError::BoundaryNotEmpty,
        InvocationBackendError::CgroupAbsent => PayloadScopeError::InvalidIdentity,
        InvocationBackendError::CgroupIo => PayloadScopeError::InvalidMembership,
    };
    match mapped {
        PayloadScopeError::BusUnavailable | PayloadScopeError::ServiceOwnerChanged => {
            warn!(
                stage = operation.stage(),
                "system bus lost during invocation-bound operation"
            );
        }
        PayloadScopeError::InvocationUnavailable | PayloadScopeError::TransportFailure => {
            warn!(
                stage = operation.stage(),
                "invocation-bound unit operation failed"
            );
        }
        _ => {}
    }
    mapped
}

fn validate_pinned_properties(
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    properties: &InvocationUnitProperties,
) -> Result<(), PayloadScopeError> {
    if !pinned.reference_held || properties.object_path != pinned.object_path {
        warn!(
            expected_invocation_id = %identity.invocation_id,
            observed_invocation_id = %properties.invocation_id,
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
    if properties.id != identity.unit_name
        || properties.control_group != control_group
        || properties.slice != format!("user-{}.slice", identity.expected_uid)
        || !properties.transient
        || !valid_payload_cgroup(control_group, identity.expected_uid, &identity.unit_name)
    {
        warn!(
            expected_invocation_id = %identity.invocation_id,
            observed_invocation_id = %properties.invocation_id,
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

impl PayloadBoundaryObserver for CgroupEventsObserver {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
    fn consume_wakeup(&mut self) -> Result<(), PayloadScopeError> {
        self.refresh()
    }
}

async fn boundary_appears_terminal(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<bool, PayloadScopeError> {
    let resolved = provider
        .resolve_by_invocation(&identity.invocation_id)
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::ResolveByInvocation, error))?;
    if resolved != pinned.object_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let properties = provider
        .read_properties(
            InvocationOperation::ReadPropertiesAfterObserver,
            &identity.invocation_id,
            &pinned.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|error| {
            map_invocation_error(InvocationOperation::ReadPropertiesAfterObserver, error)
        })?;
    validate_pinned_properties(identity, pinned, control_group, &properties)?;
    Ok(terminal_unit_state(
        &properties.active_state,
        &properties.sub_state,
    ))
}

async fn request_graceful_termination(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
    worker_pid: u32,
    launcher_pid: u32,
) -> Result<(), PayloadScopeError> {
    let members = read_members(control_group)?;
    for outside_pid in [worker_pid, launcher_pid] {
        let outside = pid_cgroup(outside_pid)?;
        if outside == control_group
            || is_ancestor(control_group, &outside)
            || members.contains(&outside_pid)
        {
            return Err(PayloadScopeError::WorkerInsideBoundary);
        }
    }
    request_graceful_termination_invocation(provider, identity, pinned_unit, control_group).await
}

async fn request_graceful_termination_invocation(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned_unit: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<(), PayloadScopeError> {
    if !pinned_unit.reference_held {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    let resolved = provider
        .resolve_by_invocation(&identity.invocation_id)
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::ResolveByInvocation, error))?;
    if resolved != pinned_unit.object_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let properties = provider
        .read_properties(
            InvocationOperation::ReadPropertiesAfterRef,
            &identity.invocation_id,
            &pinned_unit.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|error| {
            map_invocation_error(InvocationOperation::ReadPropertiesAfterRef, error)
        })?;
    validate_pinned_properties(identity, pinned_unit, control_group, &properties)?;
    if properties.active_state != "active" || properties.sub_state != "running" {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    provider
        .kill_pinned_unit(
            &identity.invocation_id,
            &pinned_unit.object_path,
            libc::SIGTERM,
        )
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::KillPinnedUnit, error))?;
    let properties_after = provider
        .read_properties(
            InvocationOperation::ReadPropertiesAfterKill,
            &identity.invocation_id,
            &pinned_unit.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|error| {
            map_invocation_error(InvocationOperation::ReadPropertiesAfterKill, error)
        })?;
    validate_pinned_properties(identity, pinned_unit, control_group, &properties_after)?;
    Ok(())
}

const MAX_CGROUP_STATE_BYTES: u64 = 4096;

enum ResolvedInvocationState {
    Present(OwnedObjectPath),
    Missing,
}

async fn resolve_invocation_for_proof(
    provider: &dyn InvocationBoundProvider,
    invocation_id: &str,
) -> Result<ResolvedInvocationState, PayloadScopeError> {
    match provider.resolve_by_invocation(invocation_id).await {
        Ok(path) => Ok(ResolvedInvocationState::Present(path)),
        Err(InvocationBackendError::NoSuchUnit | InvocationBackendError::UnknownObject) => {
            Ok(ResolvedInvocationState::Missing)
        }
        Err(error) => Err(map_invocation_error(
            InvocationOperation::ResolveByInvocation,
            error,
        )),
    }
}

async fn validate_terminal_unit(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    path: &OwnedObjectPath,
) -> Result<(), PayloadScopeError> {
    if path != &pinned.object_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let properties = provider
        .read_properties(
            InvocationOperation::ReadPropertiesDuringEmptyProof,
            &identity.invocation_id,
            path,
            &identity.unit_name,
        )
        .await
        .map_err(|error| {
            map_invocation_error(InvocationOperation::ReadPropertiesDuringEmptyProof, error)
        })?;
    validate_pinned_properties(identity, pinned, control_group, &properties)?;
    if !terminal_unit_state(&properties.active_state, &properties.sub_state) {
        return Err(PayloadScopeError::UnitNotTerminal);
    }
    Ok(())
}

fn terminal_unit_state(active: &str, sub: &str) -> bool {
    matches!((active, sub), ("inactive", "dead") | ("failed", "failed"))
}

async fn prove_empty_boundary(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    worker_pid: u32,
    launcher_pid: u32,
    leader_exit: &crate::termination::LeaderExit,
) -> Result<crate::termination::BoundaryEmptyProof, PayloadScopeError> {
    info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, "verifying payload boundary emptiness");
    if !valid_payload_cgroup(control_group, identity.expected_uid, &identity.unit_name) {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    let first = resolve_invocation_for_proof(provider, &identity.invocation_id).await?;
    if let ResolvedInvocationState::Present(path) = &first {
        validate_terminal_unit(provider, identity, pinned, control_group, path).await?;
    }

    match provider
        .read_boundary_state(&identity.invocation_id, &pinned.object_path, control_group)
        .map_err(|error| map_invocation_error(InvocationOperation::ReadBoundaryState, error))?
    {
        CgroupEmptyState::Absent if matches!(first, ResolvedInvocationState::Missing) => {}
        CgroupEmptyState::Absent => return Err(PayloadScopeError::InvalidIdentity),
        CgroupEmptyState::PresentEmpty => {}
    }
    for outside_pid in [worker_pid, launcher_pid] {
        if let Ok(path) = pid_cgroup(outside_pid) {
            if path == control_group || is_ancestor(control_group, &path) {
                return Err(PayloadScopeError::WorkerInsideBoundary);
            }
        }
    }
    let second = resolve_invocation_for_proof(provider, &identity.invocation_id).await?;
    match (&first, &second) {
        (ResolvedInvocationState::Present(first_path), ResolvedInvocationState::Present(path))
            if first_path == path =>
        {
            validate_terminal_unit(provider, identity, pinned, control_group, path).await?
        }
        (ResolvedInvocationState::Missing, ResolvedInvocationState::Missing) => {}
        _ => return Err(PayloadScopeError::UnitReplaced),
    }
    info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, "payload boundary empty proof established");
    Ok(crate::termination::BoundaryEmptyProof::new(
        identity,
        control_group,
        leader_exit.clone(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CgroupEmptyState {
    Absent,
    PresentEmpty,
}

fn read_cgroup_empty_state(control_group: &str) -> Result<CgroupEmptyState, PayloadScopeError> {
    read_cgroup_empty_state_at(Path::new(CGROUP_ROOT), control_group)
}

fn read_cgroup_empty_state_at(
    root: &Path,
    control_group: &str,
) -> Result<CgroupEmptyState, PayloadScopeError> {
    if !control_group.starts_with('/') || control_group.contains("..") {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    let directory = root.join(control_group.trim_start_matches('/'));
    let events_path = directory.join("cgroup.events");
    match fs::symlink_metadata(&events_path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Err(PayloadScopeError::InvalidMembership),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match fs::symlink_metadata(&directory) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(CgroupEmptyState::Absent)
                }
                _ => Err(PayloadScopeError::InvalidMembership),
            };
        }
        Err(_) => return Err(PayloadScopeError::InvalidMembership),
    }
    let events = read_bounded(&events_path)?;
    if parse_populated(&events)? != 0 {
        return Err(PayloadScopeError::BoundaryNotEmpty);
    }
    let procs = read_bounded(&directory.join("cgroup.procs"))?;
    if !procs.trim().is_empty() {
        return Err(PayloadScopeError::BoundaryNotEmpty);
    }
    Ok(CgroupEmptyState::PresentEmpty)
}

fn read_bounded(path: &Path) -> Result<String, PayloadScopeError> {
    let file = fs::File::open(path).map_err(|_| PayloadScopeError::InvalidMembership)?;
    let mut bytes = Vec::new();
    file.take(MAX_CGROUP_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PayloadScopeError::InvalidMembership)?;
    if bytes.len() as u64 > MAX_CGROUP_STATE_BYTES {
        return Err(PayloadScopeError::InvalidMembership);
    }
    String::from_utf8(bytes).map_err(|_| PayloadScopeError::InvalidMembership)
}

fn parse_populated(text: &str) -> Result<u8, PayloadScopeError> {
    let mut populated = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(key) = fields.next() else { continue };
        let Some(value) = fields.next() else {
            return Err(PayloadScopeError::InvalidMembership);
        };
        if fields.next().is_some() {
            return Err(PayloadScopeError::InvalidMembership);
        }
        if key == "populated" {
            if populated.is_some() {
                return Err(PayloadScopeError::InvalidMembership);
            }
            populated = Some(
                value
                    .parse::<u8>()
                    .ok()
                    .filter(|value| *value <= 1)
                    .ok_or(PayloadScopeError::InvalidMembership)?,
            );
        }
    }
    populated.ok_or(PayloadScopeError::InvalidMembership)
}

async fn release_pin(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &mut PinnedInvocationUnit,
) -> Result<(), PayloadScopeError> {
    if !pinned.reference_held {
        return Ok(());
    }
    provider
        .unref_pinned_unit(&identity.invocation_id, &pinned.object_path)
        .await
        .map_err(|error| {
            let mapped = map_invocation_error(InvocationOperation::UnrefPinnedUnit, error);
            warn!(?mapped, "pinned unit reference release failed");
            PayloadScopeError::UnrefFailed
        })?;
    pinned.reference_held = false;
    Ok(())
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
    let invocation_provider: std::sync::Arc<dyn InvocationBoundProvider> =
        std::sync::Arc::new(ZbusInvocationProvider::new(&connection));
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
    let transient: bool = unit_property!("Transient");
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
        || !transient
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
    let pinned_unit = checked!(
        pin_invocation_unit(
            invocation_provider.as_ref(),
            &unit_name,
            &invocation_id,
            &control_group,
            &slice,
        )
        .await
    );
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
        invocation_provider,
        identity,
        pinned_unit,
        control_group,
        worker_pid,
        launcher_pid,
    })
}

async fn pin_invocation_unit(
    provider: &dyn InvocationBoundProvider,
    unit_name: &str,
    invocation_id: &str,
    control_group: &str,
    slice: &str,
) -> Result<PinnedInvocationUnit, PayloadScopeError> {
    let object_path = provider
        .resolve_by_invocation(invocation_id)
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::ResolveByInvocation, error))?;
    provider
        .ref_pinned_unit(invocation_id, &object_path)
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::RefPinnedUnit, error))?;
    let validation = provider
        .read_properties(
            InvocationOperation::ReadPropertiesAfterRef,
            invocation_id,
            &object_path,
            unit_name,
        )
        .await
        .map_err(|error| map_invocation_error(InvocationOperation::ReadPropertiesAfterRef, error))
        .and_then(|properties| {
            if properties.object_path != object_path
                || properties.id != unit_name
                || properties.invocation_id != invocation_id
                || properties.control_group != control_group
                || properties.slice != slice
                || properties.active_state != "active"
                || properties.sub_state != "running"
                || !properties.transient
            {
                Err(PayloadScopeError::UnitReplaced)
            } else {
                Ok(())
            }
        });
    if let Err(error) = validation {
        let _ = provider
            .unref_pinned_unit(invocation_id, &object_path)
            .await;
        return Err(error);
    }
    info!(unit = %unit_name, invocation_id = %invocation_id, object_path = %object_path, "invocation-bound payload unit pinned");
    Ok(PinnedInvocationUnit {
        object_path,
        reference_held: true,
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
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    deadline: Instant,
    release_pin: bool,
) -> Result<(), PayloadScopeError> {
    info!(unit = %identity.unit_name, "payload scope launch cleanup started");
    match provider.read_boundary_state(&identity.invocation_id, &pinned.object_path, control_group)
    {
        Ok(CgroupEmptyState::Absent) => {
            prove_precommit_disappearance(provider, identity, pinned, control_group).await?;
            if release_pin {
                provider
                    .unref_pinned_unit(&identity.invocation_id, &pinned.object_path)
                    .await
                    .map_err(|_| PayloadScopeError::CleanupFailed)?;
            }
            info!(unit = %identity.unit_name, "payload scope disappeared boundary cleanup proved");
            return Ok(());
        }
        Ok(CgroupEmptyState::PresentEmpty) => {}
        Err(_) => return Err(PayloadScopeError::CleanupFailed),
    }
    let unit = zbus::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        pinned.object_path.as_str(),
        SYSTEMD_UNIT,
    )
    .await
    .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let observed: Vec<u8> = unit
        .get_property("InvocationID")
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    if hex_id(&observed).as_deref() != Some(identity.invocation_id.as_str())
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
        .receive_signal_with_args("JobRemoved", &[(2, identity.unit_name.as_str())])
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    let job: OwnedObjectPath = manager
        .call("StopUnit", &(identity.unit_name.as_str(), "fail"))
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    wait_job(&mut jobs, &job, deadline)
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    if release_pin {
        unit.call::<_, _, ()>("Unref", &())
            .await
            .map_err(|_| PayloadScopeError::CleanupFailed)?;
    }
    info!(unit = %identity.unit_name, "payload scope launch cleanup completed");
    Ok(())
}

async fn prove_precommit_disappearance(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
) -> Result<(), PayloadScopeError> {
    if !pinned.reference_held {
        return Err(PayloadScopeError::CleanupFailed);
    }
    let first_path = provider
        .resolve_by_invocation(&identity.invocation_id)
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    if first_path != pinned.object_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let first = provider
        .read_properties(
            InvocationOperation::ReadPropertiesDuringCleanup,
            &identity.invocation_id,
            &pinned.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    validate_disappeared_boundary_properties(identity, pinned, control_group, &first)?;
    let second_path = provider
        .resolve_by_invocation(&identity.invocation_id)
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    if second_path != first_path {
        return Err(PayloadScopeError::UnitReplaced);
    }
    let second = provider
        .read_properties(
            InvocationOperation::ReadPropertiesDuringCleanup,
            &identity.invocation_id,
            &pinned.object_path,
            &identity.unit_name,
        )
        .await
        .map_err(|_| PayloadScopeError::CleanupFailed)?;
    validate_disappeared_boundary_properties(identity, pinned, control_group, &second)?;
    if first != second {
        return Err(PayloadScopeError::UnitReplaced);
    }
    Ok(())
}

fn validate_disappeared_boundary_properties(
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    properties: &InvocationUnitProperties,
) -> Result<(), PayloadScopeError> {
    if properties.object_path != pinned.object_path
        || properties.invocation_id != identity.invocation_id
        || properties.id != identity.unit_name
        || properties.slice != format!("user-{}.slice", identity.expected_uid)
        || !properties.transient
        || (!properties.control_group.is_empty() && properties.control_group != control_group)
        || !terminal_unit_state(&properties.active_state, &properties.sub_state)
    {
        return Err(PayloadScopeError::UnitReplaced);
    }
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

fn parse_hex_id(value: &str) -> Option<Vec<u8>> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..16)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok())
        .collect()
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
    cgroup_file_named(cgroup, "cgroup.procs")
}

fn cgroup_file_named(cgroup: &str, name: &str) -> Result<PathBuf, PayloadScopeError> {
    if !cgroup.starts_with('/') || cgroup.contains("..") {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    Ok(Path::new(CGROUP_ROOT)
        .join(cgroup.trim_start_matches('/'))
        .join(name))
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
    use std::collections::VecDeque;
    use std::os::fd::OwnedFd;
    use std::sync::Mutex;

    const INVOCATION_A: &str = "00112233445566778899aabbccddeeff";
    const INVOCATION_B: &str = "ffeeddccbbaa99887766554433221100";
    const UNIT_NAME: &str = "niralis-payload-00112233445566778899aabbccddeeff.scope";
    const CONTROL_GROUP: &str =
        "/user.slice/user-1000.slice/niralis-payload-00112233445566778899aabbccddeeff.scope";

    fn path_a() -> OwnedObjectPath {
        OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/path_a").unwrap()
    }

    fn path_b() -> OwnedObjectPath {
        OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/path_b").unwrap()
    }

    fn identity_a() -> PayloadScopeIdentity {
        PayloadScopeIdentity {
            unit_name: UNIT_NAME.into(),
            invocation_id: INVOCATION_A.into(),
            expected_uid: 1000,
            logind_session_id: LogindSessionId::new("fixture-session".into()).unwrap(),
        }
    }

    fn properties_a() -> InvocationUnitProperties {
        InvocationUnitProperties {
            object_path: path_a(),
            id: UNIT_NAME.into(),
            invocation_id: INVOCATION_A.into(),
            control_group: CONTROL_GROUP.into(),
            slice: "user-1000.slice".into(),
            transient: true,
            active_state: "active".into(),
            sub_state: "running".into(),
        }
    }

    fn terminal_properties_a() -> InvocationUnitProperties {
        InvocationUnitProperties {
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            ..properties_a()
        }
    }

    #[derive(Debug)]
    enum ScriptedInvocationResponse {
        Success,
        Resolved(OwnedObjectPath),
        Properties(InvocationUnitProperties),
        BoundaryState(CgroupEmptyState),
        NoSuchUnit,
        UnknownObject,
        BusDisconnected,
        ServiceOwnerChanged,
        TransportFailure,
        BoundaryNotEmpty,
        CgroupIoFailure,
        UnrefFailure,
    }

    #[derive(Debug)]
    struct ScriptedInvocationStep {
        expected_operation: InvocationOperation,
        expected_invocation_id: String,
        expected_object_path: Option<OwnedObjectPath>,
        expected_unit_name: Option<String>,
        response: ScriptedInvocationResponse,
    }

    impl ScriptedInvocationStep {
        fn new(operation: InvocationOperation, response: ScriptedInvocationResponse) -> Self {
            Self {
                expected_operation: operation,
                expected_invocation_id: INVOCATION_A.into(),
                expected_object_path: (operation != InvocationOperation::ResolveByInvocation)
                    .then(path_a),
                expected_unit_name: matches!(
                    operation,
                    InvocationOperation::ReadPropertiesAfterRef
                        | InvocationOperation::ReadPropertiesAfterKill
                        | InvocationOperation::ReadPropertiesAfterObserver
                        | InvocationOperation::ReadPropertiesDuringEmptyProof
                        | InvocationOperation::ReadPropertiesDuringCleanup
                )
                .then(|| UNIT_NAME.into()),
                response,
            }
        }
    }

    struct ScriptedInvocationBackend {
        steps: Mutex<VecDeque<ScriptedInvocationStep>>,
    }

    impl ScriptedInvocationBackend {
        fn new(steps: Vec<ScriptedInvocationStep>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
            }
        }

        fn consume(
            &self,
            operation: InvocationOperation,
            invocation_id: &str,
            object_path: Option<&OwnedObjectPath>,
            unit_name: Option<&str>,
        ) -> ScriptedInvocationResponse {
            let mut steps = self.steps.lock().unwrap();
            let expected = steps.pop_front().unwrap_or_else(|| {
                panic!(
                    "unexpected invocation operation with no scripted step: observed={operation:?}({object_path:?})"
                )
            });
            assert_eq!(
                expected.expected_operation, operation,
                "scripted invocation operation out of order\nexpected: {:?}({:?})\nobserved: {:?}({:?})",
                expected.expected_operation,
                expected.expected_object_path,
                operation,
                object_path
            );
            assert_eq!(expected.expected_invocation_id, invocation_id);
            assert_eq!(expected.expected_object_path.as_ref(), object_path);
            assert_eq!(expected.expected_unit_name.as_deref(), unit_name);
            expected.response
        }

        fn assert_consumed(&self) {
            let steps = self.steps.lock().unwrap();
            assert!(
                steps.is_empty(),
                "scripted invocation steps left unconsumed: {steps:#?}"
            );
        }
    }

    fn response_error(response: ScriptedInvocationResponse) -> InvocationBackendError {
        match response {
            ScriptedInvocationResponse::NoSuchUnit => InvocationBackendError::NoSuchUnit,
            ScriptedInvocationResponse::UnknownObject => InvocationBackendError::UnknownObject,
            ScriptedInvocationResponse::BusDisconnected => InvocationBackendError::BusDisconnected,
            ScriptedInvocationResponse::ServiceOwnerChanged => {
                InvocationBackendError::ServiceOwnerChanged
            }
            ScriptedInvocationResponse::TransportFailure => InvocationBackendError::Transport,
            ScriptedInvocationResponse::BoundaryNotEmpty => {
                InvocationBackendError::BoundaryNotEmpty
            }
            ScriptedInvocationResponse::CgroupIoFailure => InvocationBackendError::CgroupIo,
            ScriptedInvocationResponse::UnrefFailure => InvocationBackendError::Transport,
            response => panic!("script response has wrong type for operation: {response:?}"),
        }
    }

    impl InvocationBoundProvider for ScriptedInvocationBackend {
        fn resolve_by_invocation<'a>(
            &'a self,
            expected_invocation_id: &'a str,
        ) -> InvocationFuture<'a, OwnedObjectPath> {
            Box::pin(async move {
                match self.consume(
                    InvocationOperation::ResolveByInvocation,
                    expected_invocation_id,
                    None,
                    None,
                ) {
                    ScriptedInvocationResponse::Resolved(path) => Ok(path),
                    response => Err(response_error(response)),
                }
            })
        }

        fn ref_pinned_unit<'a>(
            &'a self,
            expected_invocation_id: &'a str,
            expected_object_path: &'a OwnedObjectPath,
        ) -> InvocationFuture<'a, ()> {
            Box::pin(async move {
                match self.consume(
                    InvocationOperation::RefPinnedUnit,
                    expected_invocation_id,
                    Some(expected_object_path),
                    None,
                ) {
                    ScriptedInvocationResponse::Success => Ok(()),
                    response => Err(response_error(response)),
                }
            })
        }

        fn read_properties<'a>(
            &'a self,
            operation: InvocationOperation,
            expected_invocation_id: &'a str,
            expected_object_path: &'a OwnedObjectPath,
            expected_unit_name: &'a str,
        ) -> InvocationFuture<'a, InvocationUnitProperties> {
            Box::pin(async move {
                match self.consume(
                    operation,
                    expected_invocation_id,
                    Some(expected_object_path),
                    Some(expected_unit_name),
                ) {
                    ScriptedInvocationResponse::Properties(properties) => Ok(properties),
                    response => Err(response_error(response)),
                }
            })
        }

        fn kill_pinned_unit<'a>(
            &'a self,
            expected_invocation_id: &'a str,
            expected_object_path: &'a OwnedObjectPath,
            signal: libc::c_int,
        ) -> InvocationFuture<'a, ()> {
            Box::pin(async move {
                assert_eq!(signal, libc::SIGTERM);
                match self.consume(
                    InvocationOperation::KillPinnedUnit,
                    expected_invocation_id,
                    Some(expected_object_path),
                    None,
                ) {
                    ScriptedInvocationResponse::Success => Ok(()),
                    response => Err(response_error(response)),
                }
            })
        }

        fn create_boundary_observer(
            &self,
            expected_invocation_id: &str,
            expected_object_path: &OwnedObjectPath,
            _control_group: &str,
        ) -> Result<Box<dyn PayloadBoundaryObserver>, InvocationBackendError> {
            match self.consume(
                InvocationOperation::CreateBoundaryObserver,
                expected_invocation_id,
                Some(expected_object_path),
                None,
            ) {
                ScriptedInvocationResponse::Success => {
                    let fd = unsafe { libc::eventfd(1, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
                    assert!(fd >= 0);
                    Ok(Box::new(ScriptedObserver(unsafe {
                        OwnedFd::from_raw_fd(fd)
                    })))
                }
                response => Err(response_error(response)),
            }
        }

        fn read_boundary_state(
            &self,
            expected_invocation_id: &str,
            expected_object_path: &OwnedObjectPath,
            _control_group: &str,
        ) -> Result<CgroupEmptyState, InvocationBackendError> {
            match self.consume(
                InvocationOperation::ReadBoundaryState,
                expected_invocation_id,
                Some(expected_object_path),
                None,
            ) {
                ScriptedInvocationResponse::BoundaryState(state) => Ok(state),
                response => Err(response_error(response)),
            }
        }

        fn unref_pinned_unit<'a>(
            &'a self,
            expected_invocation_id: &'a str,
            expected_object_path: &'a OwnedObjectPath,
        ) -> InvocationFuture<'a, ()> {
            Box::pin(async move {
                match self.consume(
                    InvocationOperation::UnrefPinnedUnit,
                    expected_invocation_id,
                    Some(expected_object_path),
                    None,
                ) {
                    ScriptedInvocationResponse::Success => Ok(()),
                    response => Err(response_error(response)),
                }
            })
        }
    }

    struct ScriptedObserver(OwnedFd);
    impl PayloadBoundaryObserver for ScriptedObserver {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
        fn poll_events(&self) -> libc::c_short {
            libc::POLLIN
        }
        fn consume_wakeup(&mut self) -> Result<(), PayloadScopeError> {
            let mut value = 0_u64;
            (unsafe { libc::read(self.0.as_raw_fd(), (&mut value as *mut u64).cast(), 8) } == 8)
                .then_some(())
                .ok_or(PayloadScopeError::ObserverFailed)
        }
    }

    fn pinned_a() -> PinnedInvocationUnit {
        PinnedInvocationUnit {
            object_path: path_a(),
            reference_held: true,
        }
    }

    fn kill_steps(kill_response: ScriptedInvocationResponse) -> Vec<ScriptedInvocationStep> {
        vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterRef,
                ScriptedInvocationResponse::Properties(properties_a()),
            ),
            ScriptedInvocationStep::new(InvocationOperation::KillPinnedUnit, kill_response),
        ]
    }

    #[test]
    fn precommit_cgroup_disappearance_requires_two_coherent_invocation_resolutions() {
        let mut terminal = terminal_properties_a();
        terminal.control_group.clear();
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryState(CgroupEmptyState::Absent),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringCleanup,
                ScriptedInvocationResponse::Properties(terminal.clone()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringCleanup,
                ScriptedInvocationResponse::Properties(terminal),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::UnrefPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
        ]);
        assert_eq!(
            backend
                .read_boundary_state(INVOCATION_A, &path_a(), CONTROL_GROUP)
                .unwrap(),
            CgroupEmptyState::Absent
        );
        let mut pinned = pinned_a();
        async_io::block_on(prove_precommit_disappearance(
            &backend,
            &identity_a(),
            &pinned,
            CONTROL_GROUP,
        ))
        .unwrap();
        async_io::block_on(release_pin(&backend, &identity_a(), &mut pinned)).unwrap();
        assert!(!pinned.reference_held);
        backend.assert_consumed();
    }

    #[test]
    fn replacement_between_precommit_disappearance_revalidations_preserves_pin() {
        let mut terminal = terminal_properties_a();
        terminal.control_group.clear();
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringCleanup,
                ScriptedInvocationResponse::Properties(terminal),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_b()),
            ),
        ]);
        let pinned = pinned_a();
        assert_eq!(
            async_io::block_on(prove_precommit_disappearance(
                &backend,
                &identity_a(),
                &pinned,
                CONTROL_GROUP,
            )),
            Err(PayloadScopeError::UnitReplaced)
        );
        assert!(pinned.reference_held);
        backend.assert_consumed();
    }

    #[test]
    fn invocation_removed_before_resolve_never_falls_back_to_name() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::NoSuchUnit,
        )]);
        let error = async_io::block_on(request_graceful_termination_invocation(
            &backend,
            &identity_a(),
            &pinned_a(),
            CONTROL_GROUP,
        ))
        .unwrap_err();
        assert_eq!(error, PayloadScopeError::InvocationUnavailable);
        backend.assert_consumed();
    }

    #[test]
    fn invocation_removed_between_resolve_and_ref_never_kills() {
        for response in [
            ScriptedInvocationResponse::UnknownObject,
            ScriptedInvocationResponse::NoSuchUnit,
        ] {
            let backend = ScriptedInvocationBackend::new(vec![
                ScriptedInvocationStep::new(
                    InvocationOperation::ResolveByInvocation,
                    ScriptedInvocationResponse::Resolved(path_a()),
                ),
                ScriptedInvocationStep::new(InvocationOperation::RefPinnedUnit, response),
            ]);
            let error = async_io::block_on(pin_invocation_unit(
                &backend,
                UNIT_NAME,
                INVOCATION_A,
                CONTROL_GROUP,
                "user-1000.slice",
            ))
            .unwrap_err();
            assert_eq!(error, PayloadScopeError::InvocationUnavailable);
            backend.assert_consumed();
        }
    }

    fn assert_post_ref_mismatch(properties: InvocationUnitProperties) {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::RefPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterRef,
                ScriptedInvocationResponse::Properties(properties),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::UnrefPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
        ]);
        assert_eq!(
            async_io::block_on(pin_invocation_unit(
                &backend,
                UNIT_NAME,
                INVOCATION_A,
                CONTROL_GROUP,
                "user-1000.slice",
            ))
            .unwrap_err(),
            PayloadScopeError::UnitReplaced
        );
        backend.assert_consumed();
    }

    #[test]
    fn post_ref_invocation_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            invocation_id: INVOCATION_B.into(),
            ..properties_a()
        });
    }

    #[test]
    fn post_ref_unit_id_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            id: "replacement.scope".into(),
            ..properties_a()
        });
    }

    #[test]
    fn post_ref_control_group_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            control_group: "/user.slice/user-1000.slice/replacement.scope".into(),
            ..properties_a()
        });
    }

    #[test]
    fn post_ref_slice_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            slice: "system.slice".into(),
            ..properties_a()
        });
    }

    #[test]
    fn post_ref_non_transient_unit_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            transient: false,
            ..properties_a()
        });
    }

    #[test]
    fn post_ref_object_path_mismatch_prevents_kill() {
        assert_post_ref_mismatch(InvocationUnitProperties {
            object_path: path_b(),
            ..properties_a()
        });
    }

    #[test]
    fn pinned_path_invalidated_before_kill_fails_closed() {
        for response in [
            ScriptedInvocationResponse::UnknownObject,
            ScriptedInvocationResponse::NoSuchUnit,
        ] {
            let backend = ScriptedInvocationBackend::new(kill_steps(response));
            assert_eq!(
                async_io::block_on(request_graceful_termination_invocation(
                    &backend,
                    &identity_a(),
                    &pinned_a(),
                    CONTROL_GROUP,
                ))
                .unwrap_err(),
                PayloadScopeError::InvocationUnavailable
            );
            backend.assert_consumed();
        }
    }

    #[test]
    fn bus_loss_before_kill_preserves_pinned_identity() {
        let backend =
            ScriptedInvocationBackend::new(kill_steps(ScriptedInvocationResponse::BusDisconnected));
        let pinned = pinned_a();
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &backend,
                &identity_a(),
                &pinned,
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::BusUnavailable
        );
        assert!(pinned.reference_held);
        assert_eq!(pinned.object_path, path_a());
        backend.assert_consumed();
    }

    #[test]
    fn pinned_unit_never_reinterprets_reused_name() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterRef,
                ScriptedInvocationResponse::Properties(properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::KillPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterKill,
                ScriptedInvocationResponse::Properties(properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::CreateBoundaryObserver,
                ScriptedInvocationResponse::Success,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesAfterObserver,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryState(CgroupEmptyState::PresentEmpty),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::UnrefPinnedUnit,
                ScriptedInvocationResponse::Success,
            ),
        ]);
        let identity = identity_a();
        let mut pinned = pinned_a();
        async_io::block_on(request_graceful_termination_invocation(
            &backend,
            &identity,
            &pinned,
            CONTROL_GROUP,
        ))
        .unwrap();
        let mut observer = backend
            .create_boundary_observer(INVOCATION_A, &path_a(), CONTROL_GROUP)
            .unwrap();
        observer.consume_wakeup().unwrap();
        assert!(async_io::block_on(boundary_appears_terminal(
            &backend,
            &identity,
            &pinned,
            CONTROL_GROUP,
        ))
        .unwrap());
        async_io::block_on(prove_empty_boundary(
            &backend,
            &identity,
            &pinned,
            CONTROL_GROUP,
            u32::MAX,
            u32::MAX,
            &crate::termination::LeaderExit::ExitedZero,
        ))
        .unwrap();
        async_io::block_on(release_pin(&backend, &identity, &mut pinned)).unwrap();
        assert!(!pinned.reference_held);
        backend.assert_consumed();
    }

    #[test]
    fn replacement_after_kill_does_not_receive_second_operation() {
        let mut steps = kill_steps(ScriptedInvocationResponse::Success);
        steps.push(ScriptedInvocationStep::new(
            InvocationOperation::ReadPropertiesAfterKill,
            ScriptedInvocationResponse::NoSuchUnit,
        ));
        let backend = ScriptedInvocationBackend::new(steps);
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::InvocationUnavailable
        );
        backend.assert_consumed();
    }

    #[test]
    fn replacement_path_after_kill_is_identity_change() {
        let mut steps = kill_steps(ScriptedInvocationResponse::Success);
        steps.push(ScriptedInvocationStep::new(
            InvocationOperation::ReadPropertiesAfterKill,
            ScriptedInvocationResponse::Properties(InvocationUnitProperties {
                object_path: path_b(),
                invocation_id: INVOCATION_B.into(),
                ..properties_a()
            }),
        ));
        let backend = ScriptedInvocationBackend::new(steps);
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::UnitReplaced
        );
        backend.assert_consumed();
    }

    #[test]
    fn bus_loss_after_kill_does_not_produce_candidate() {
        let mut steps = kill_steps(ScriptedInvocationResponse::Success);
        steps.push(ScriptedInvocationStep::new(
            InvocationOperation::ReadPropertiesAfterKill,
            ScriptedInvocationResponse::BusDisconnected,
        ));
        let backend = ScriptedInvocationBackend::new(steps);
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::BusUnavailable
        );
        backend.assert_consumed();
    }

    #[test]
    fn observer_wakeup_during_bus_loss_does_not_produce_candidate() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::CreateBoundaryObserver,
                ScriptedInvocationResponse::Success,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::BusDisconnected,
            ),
        ]);
        let mut observer = backend
            .create_boundary_observer(INVOCATION_A, &path_a(), CONTROL_GROUP)
            .unwrap();
        observer.consume_wakeup().unwrap();
        assert_eq!(
            async_io::block_on(boundary_appears_terminal(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::BusUnavailable
        );
        backend.assert_consumed();
    }

    #[test]
    fn replacement_during_empty_proof_prevents_finalization() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::Resolved(path_b()),
        )]);
        assert_eq!(
            async_io::block_on(prove_empty_boundary(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
                u32::MAX,
                u32::MAX,
                &crate::termination::LeaderExit::ExitedZero,
            ))
            .unwrap_err(),
            PayloadScopeError::UnitReplaced
        );
        backend.assert_consumed();
    }

    #[test]
    fn replacement_between_empty_proof_revalidations_is_detected() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryState(CgroupEmptyState::PresentEmpty),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_b()),
            ),
        ]);
        assert_eq!(
            async_io::block_on(prove_empty_boundary(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
                u32::MAX,
                u32::MAX,
                &crate::termination::LeaderExit::ExitedZero,
            ))
            .unwrap_err(),
            PayloadScopeError::UnitReplaced
        );
        backend.assert_consumed();
    }

    #[test]
    fn observer_zero_then_populated_one_prevents_proof() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryNotEmpty,
            ),
        ]);
        assert_eq!(
            async_io::block_on(prove_empty_boundary(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
                u32::MAX,
                u32::MAX,
                &crate::termination::LeaderExit::ExitedZero,
            ))
            .unwrap_err(),
            PayloadScopeError::BoundaryNotEmpty
        );
        backend.assert_consumed();
    }

    #[test]
    fn no_such_unit_empty_proof_requires_two_missing_resolutions_and_absent_cgroup() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::NoSuchUnit,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryState(CgroupEmptyState::Absent),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::NoSuchUnit,
            ),
        ]);
        async_io::block_on(prove_empty_boundary(
            &backend,
            &identity_a(),
            &pinned_a(),
            CONTROL_GROUP,
            u32::MAX,
            u32::MAX,
            &crate::termination::LeaderExit::ExitedZero,
        ))
        .unwrap();
        backend.assert_consumed();
    }

    #[test]
    fn no_such_unit_with_populated_boundary_never_proves_empty() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::NoSuchUnit,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryNotEmpty,
            ),
        ]);
        assert_eq!(
            async_io::block_on(prove_empty_boundary(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
                u32::MAX,
                u32::MAX,
                &crate::termination::LeaderExit::ExitedZero,
            ))
            .unwrap_err(),
            PayloadScopeError::BoundaryNotEmpty
        );
        backend.assert_consumed();
    }

    #[test]
    fn unref_is_never_called_before_empty_proof() {
        let backend = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::Resolved(path_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadPropertiesDuringEmptyProof,
                ScriptedInvocationResponse::Properties(terminal_properties_a()),
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::BoundaryNotEmpty,
            ),
        ]);
        let result = async_io::block_on(prove_empty_boundary(
            &backend,
            &identity_a(),
            &pinned_a(),
            CONTROL_GROUP,
            u32::MAX,
            u32::MAX,
            &crate::termination::LeaderExit::ExitedZero,
        ));
        assert_eq!(result.unwrap_err(), PayloadScopeError::BoundaryNotEmpty);
        backend.assert_consumed();
    }

    #[test]
    fn service_owner_change_is_not_accepted_as_a_valid_pin() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::ServiceOwnerChanged,
        )]);
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &backend,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::ServiceOwnerChanged
        );
        backend.assert_consumed();
    }

    #[test]
    fn typed_transport_cgroup_and_unref_failures_remain_distinct() {
        let transport = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::TransportFailure,
        )]);
        assert_eq!(
            async_io::block_on(request_graceful_termination_invocation(
                &transport,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
            ))
            .unwrap_err(),
            PayloadScopeError::TransportFailure
        );
        transport.assert_consumed();

        let cgroup = ScriptedInvocationBackend::new(vec![
            ScriptedInvocationStep::new(
                InvocationOperation::ResolveByInvocation,
                ScriptedInvocationResponse::NoSuchUnit,
            ),
            ScriptedInvocationStep::new(
                InvocationOperation::ReadBoundaryState,
                ScriptedInvocationResponse::CgroupIoFailure,
            ),
        ]);
        assert_eq!(
            async_io::block_on(prove_empty_boundary(
                &cgroup,
                &identity_a(),
                &pinned_a(),
                CONTROL_GROUP,
                u32::MAX,
                u32::MAX,
                &crate::termination::LeaderExit::ExitedZero,
            ))
            .unwrap_err(),
            PayloadScopeError::InvalidMembership
        );
        cgroup.assert_consumed();

        let unref = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::UnrefPinnedUnit,
            ScriptedInvocationResponse::UnrefFailure,
        )]);
        let mut pinned = pinned_a();
        assert_eq!(
            async_io::block_on(release_pin(&unref, &identity_a(), &mut pinned)).unwrap_err(),
            PayloadScopeError::UnrefFailed
        );
        assert!(pinned.reference_held);
        unref.assert_consumed();
    }

    #[test]
    #[should_panic(expected = "scripted invocation operation out of order")]
    fn scripted_backend_rejects_wrong_operation_order() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ReadPropertiesAfterRef,
            ScriptedInvocationResponse::Properties(properties_a()),
        )]);
        let _ =
            async_io::block_on(backend.kill_pinned_unit(INVOCATION_A, &path_a(), libc::SIGTERM));
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn scripted_backend_rejects_wrong_object_path() {
        let mut step = ScriptedInvocationStep::new(
            InvocationOperation::RefPinnedUnit,
            ScriptedInvocationResponse::Success,
        );
        step.expected_object_path = Some(path_b());
        let backend = ScriptedInvocationBackend::new(vec![step]);
        let _ = async_io::block_on(backend.ref_pinned_unit(INVOCATION_A, &path_a()));
    }

    #[test]
    #[should_panic(expected = "unexpected invocation operation with no scripted step")]
    fn scripted_backend_rejects_duplicate_ref() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::RefPinnedUnit,
            ScriptedInvocationResponse::Success,
        )]);
        async_io::block_on(backend.ref_pinned_unit(INVOCATION_A, &path_a())).unwrap();
        let _ = async_io::block_on(backend.ref_pinned_unit(INVOCATION_A, &path_a()));
    }

    #[test]
    #[should_panic(expected = "steps left unconsumed")]
    fn scripted_backend_rejects_unconsumed_steps() {
        let backend = ScriptedInvocationBackend::new(vec![ScriptedInvocationStep::new(
            InvocationOperation::ResolveByInvocation,
            ScriptedInvocationResponse::Resolved(path_a()),
        )]);
        backend.assert_consumed();
    }

    #[test]
    fn manager_kill_unit_is_unrepresentable_in_running_provider() {
        let source = include_str!("payload_scope.rs");
        let provider = source
            .split("trait InvocationBoundProvider")
            .nth(1)
            .unwrap()
            .split("impl InvocationBoundProvider for ZbusInvocationProvider")
            .next()
            .unwrap();
        assert!(!provider.contains("kill_unit_by_name"));
        assert_eq!(provider.matches("fn kill_pinned_unit").count(), 1);
        assert!(!source.contains("\"KillUnit\""));
        assert!(source.contains("unit.call::<_, _, ()>(\"Kill\", &(\"all\", signal))"));
    }

    #[test]
    fn scripted_backend_is_test_only_and_not_runtime_selectable() {
        let source = include_str!("payload_scope.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let main = include_str!("main.rs");
        let protocol = include_str!("../../niralis-session/src/protocol.rs");
        assert!(!production.contains("ScriptedInvocationBackend"));
        assert!(!production.contains("NIRALIS_SYSTEMD_BACKEND"));
        assert!(!main.contains("NIRALIS_SYSTEMD_BACKEND"));
        assert!(!protocol.contains("ScriptedInvocation"));
        assert!(production.contains("ZbusInvocationProvider::new(&connection)"));
    }

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

    #[test]
    fn invocation_id_round_trips_as_dbus_bytes() {
        let value = "00112233445566778899aabbccddeeff";
        let bytes = parse_hex_id(value).unwrap();
        assert_eq!(hex_id(&bytes).as_deref(), Some(value));
        assert!(parse_hex_id("0011").is_none());
        assert!(parse_hex_id("zz112233445566778899aabbccddeeff").is_none());
    }

    #[test]
    fn running_termination_has_no_manager_killunit_fallback() {
        let source = include_str!("payload_scope.rs");
        assert!(!source.contains("\"KillUnit\""));
        assert!(source.contains("\"GetUnitByInvocationID\""));
        assert!(source.contains("\"Kill\", &(\"all\", signal)"));
    }

    #[test]
    fn cgroup_events_parser_is_bounded_and_requires_unique_populated_state() {
        assert_eq!(parse_populated("frozen 0\npopulated 0\n"), Ok(0));
        assert_eq!(parse_populated("populated 1\nfrozen 0\n"), Ok(1));
        assert_eq!(
            parse_populated("frozen 0\n"),
            Err(PayloadScopeError::InvalidMembership)
        );
        assert_eq!(
            parse_populated("populated x\n"),
            Err(PayloadScopeError::InvalidMembership)
        );
        assert_eq!(
            parse_populated("populated 0\npopulated 0\n"),
            Err(PayloadScopeError::InvalidMembership)
        );
    }

    #[test]
    fn unit_terminal_states_are_explicit() {
        assert!(terminal_unit_state("inactive", "dead"));
        assert!(terminal_unit_state("failed", "failed"));
        for state in [
            ("active", "running"),
            ("active", "exited"),
            ("activating", "start"),
            ("deactivating", "stop-sigterm"),
            ("inactive", "failed"),
        ] {
            assert!(!terminal_unit_state(state.0, state.1), "{state:?}");
        }
    }

    #[test]
    fn bounded_reader_rejects_oversized_state() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state");
        std::fs::write(&path, vec![b'x'; MAX_CGROUP_STATE_BYTES as usize + 1]).unwrap();
        assert_eq!(
            read_bounded(&path).err(),
            Some(PayloadScopeError::InvalidMembership)
        );
    }

    #[test]
    fn empty_cgroup_requires_populated_zero_and_empty_procs() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("user.slice/user-1000.slice/test.scope");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
        std::fs::write(directory.join("cgroup.procs"), "").unwrap();
        assert!(matches!(
            read_cgroup_empty_state_at(root.path(), "/user.slice/user-1000.slice/test.scope"),
            Ok(CgroupEmptyState::PresentEmpty)
        ));

        std::fs::write(directory.join("cgroup.events"), "populated 1\n").unwrap();
        assert_eq!(
            read_cgroup_empty_state_at(root.path(), "/user.slice/user-1000.slice/test.scope").err(),
            Some(PayloadScopeError::BoundaryNotEmpty)
        );
        std::fs::write(directory.join("cgroup.events"), "populated 0\n").unwrap();
        std::fs::write(directory.join("cgroup.procs"), "4242\n").unwrap();
        assert_eq!(
            read_cgroup_empty_state_at(root.path(), "/user.slice/user-1000.slice/test.scope").err(),
            Some(PayloadScopeError::BoundaryNotEmpty)
        );
    }

    #[test]
    fn absent_original_cgroup_is_distinct_from_unreadable_state() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_cgroup_empty_state_at(root.path(), "/missing.scope"),
            Ok(CgroupEmptyState::Absent)
        ));
        let directory = root.path().join("present.scope");
        std::fs::create_dir_all(&directory).unwrap();
        assert_eq!(
            read_cgroup_empty_state_at(root.path(), "/present.scope").err(),
            Some(PayloadScopeError::InvalidMembership)
        );
    }
}
