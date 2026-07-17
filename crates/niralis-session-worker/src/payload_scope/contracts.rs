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
