use std::cell::Cell;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(feature = "worker-test-fixtures")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use niralis_auth::{AuthError, Authenticator, PamAuthenticator};
use niralis_session::{
    read_control_request, read_envelope, write_envelope, SessionError, StartedSession,
    WorkerControlRequest, WorkerErrorCode, WorkerRequest, WorkerResponse, WorkerSessionFailureCode,
    WORKER_CONTROL_PROTOCOL_VERSION,
};
use tracing::{debug, info, warn};

use crate::identity::{
    NssSupplementaryGroupsResolver, NssUnixIdentityResolver, ResolvedUnixCredentials,
    SupplementaryGroupsResolver, UnixIdentityResolver,
};
use crate::logind::{LogindSessionIdentity, LogindSessionResolver, SdLoginResolver};
use crate::privilege_drop::PrivilegeDropTarget;
use crate::selinux::{LinuxSelinuxContextManager, SelinuxContextManager};
use crate::session_child::{
    ProcessSessionChildRunnerFactory, SessionChildExpectation, SessionChildRunnerFactory,
    SessionChildRuntimeContext, SessionChildTerminalContext, SessionChildUnixPath,
};
use crate::smoke::authorize_real_graphical_smoke_for_runtime;
use crate::vt::{LinuxVirtualTerminalAllocator, VirtualTerminalAllocator, VirtualTerminalGuard};

pub trait WorkerAuthenticatorFactory: Send + Sync {
    fn build(&self, pam_service: &str) -> Box<dyn Authenticator>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerLaunchPhase {
    PendingHandoffBeforeScope,
    ScopePinnedBeforeAck,
    AckReceivedBeforeCommitExec,
}

pub(crate) trait LaunchPhaseGate: Send + Sync {
    fn reached(&self, phase: WorkerLaunchPhase) -> Result<(), SessionError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NoopLaunchPhaseGate;

impl LaunchPhaseGate for NoopLaunchPhaseGate {
    fn reached(&self, _phase: WorkerLaunchPhase) -> Result<(), SessionError> {
        Ok(())
    }
}

pub struct WorkerDependencies<'a, F, I, G, C, L> {
    pub authenticator_factory: &'a F,
    pub identity_resolver: &'a I,
    pub supplementary_groups_resolver: &'a G,
    pub session_child_runner_factory: &'a C,
    pub logind_resolver: &'a L,
    pub virtual_terminal_allocator: &'a dyn VirtualTerminalAllocator,
    pub runtime_dir_validator: &'a dyn RuntimeDirValidator,
    pub selinux_context_manager: &'a dyn SelinuxContextManager,
    pub payload_scope_manager: &'a dyn crate::payload_scope::PayloadScopeManager,
    pub launch_phase_gate: &'a dyn LaunchPhaseGate,
}

pub trait RuntimeDirValidator: Send + Sync {
    fn validate(&self, path: &Path, uid: u32) -> Result<(), RuntimeDirValidationError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxRuntimeDirValidator;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RuntimeDirValidationError {
    #[error("runtime directory path is invalid")]
    InvalidPath,
    #[error("runtime directory metadata is invalid")]
    InvalidMetadata,
    #[error("runtime directory owner or mode is invalid")]
    WrongOwnerOrMode,
}

impl RuntimeDirValidator for LinuxRuntimeDirValidator {
    fn validate(&self, path: &Path, uid: u32) -> Result<(), RuntimeDirValidationError> {
        if !path.is_absolute() {
            return Err(RuntimeDirValidationError::InvalidPath);
        }
        let link = std::fs::symlink_metadata(path)
            .map_err(|_| RuntimeDirValidationError::InvalidMetadata)?;
        if link.file_type().is_symlink() || !link.is_dir() {
            return Err(RuntimeDirValidationError::InvalidMetadata);
        }
        let metadata =
            std::fs::metadata(path).map_err(|_| RuntimeDirValidationError::InvalidMetadata)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != uid
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(RuntimeDirValidationError::WrongOwnerOrMode);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct StubRuntimeDirValidator;

impl RuntimeDirValidator for StubRuntimeDirValidator {
    fn validate(&self, _path: &Path, _uid: u32) -> Result<(), RuntimeDirValidationError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct PamAuthenticatorFactory;

impl WorkerAuthenticatorFactory for PamAuthenticatorFactory {
    fn build(&self, pam_service: &str) -> Box<dyn Authenticator> {
        Box::new(PamAuthenticator::new(pam_service))
    }
}

pub fn run_worker_process<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), SessionError> {
    run_worker_process_with_dependencies(
        reader,
        writer,
        WorkerDependencies {
            authenticator_factory: &PamAuthenticatorFactory,
            identity_resolver: &NssUnixIdentityResolver,
            supplementary_groups_resolver: &NssSupplementaryGroupsResolver,
            session_child_runner_factory: &ProcessSessionChildRunnerFactory,
            logind_resolver: &SdLoginResolver,
            virtual_terminal_allocator: &LinuxVirtualTerminalAllocator,
            runtime_dir_validator: &LinuxRuntimeDirValidator,
            selinux_context_manager: &LinuxSelinuxContextManager,
            payload_scope_manager: &crate::payload_scope::SystemdPayloadScopeManager,
            launch_phase_gate: &NoopLaunchPhaseGate,
        },
    )
}

thread_local! {
    static WORKER_SIGNAL_FD: Cell<i32> = const { Cell::new(-1) };
    static SUPERVISOR_CHANNEL_FD: Cell<i32> = const { Cell::new(-1) };
}

#[cfg(feature = "worker-test-fixtures")]
static FIXTURE_GRACE_MILLIS: AtomicU64 = AtomicU64::new(5_000);
#[cfg(feature = "worker-test-fixtures")]
static FIXTURE_WATCHDOG_AUTHORIZED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "worker-test-fixtures")]
static FIXTURE_CONTROL_UID: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "worker-test-fixtures")]
pub(crate) fn set_fixture_grace_period(duration: Duration) {
    let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    FIXTURE_GRACE_MILLIS.store(millis.max(1), Ordering::SeqCst);
}

#[cfg(feature = "worker-test-fixtures")]
pub(crate) fn authorize_fixture_launch_watchdog() {
    FIXTURE_WATCHDOG_AUTHORIZED.store(true, Ordering::SeqCst);
}

#[cfg(feature = "worker-test-fixtures")]
pub(crate) fn set_fixture_control_uid(uid: u32) {
    FIXTURE_CONTROL_UID.store(u64::from(uid), Ordering::SeqCst);
}

fn internal_control_peer_uid() -> u32 {
    #[cfg(feature = "worker-test-fixtures")]
    {
        u32::try_from(FIXTURE_CONTROL_UID.load(Ordering::SeqCst)).unwrap_or(0)
    }
    #[cfg(not(feature = "worker-test-fixtures"))]
    {
        0
    }
}

fn authorize_launch_watchdog(
    session_id: &str,
) -> Result<Duration, crate::smoke::RealGraphicalSmokeGuardError> {
    #[cfg(feature = "worker-test-fixtures")]
    if FIXTURE_WATCHDOG_AUTHORIZED.load(Ordering::SeqCst) {
        return Ok(Duration::from_secs(300));
    }
    authorize_real_graphical_smoke_for_runtime(session_id)
}

fn configured_session_termination_grace() -> Duration {
    #[cfg(feature = "worker-test-fixtures")]
    {
        Duration::from_millis(FIXTURE_GRACE_MILLIS.load(Ordering::SeqCst))
    }
    #[cfg(not(feature = "worker-test-fixtures"))]
    {
        SESSION_TERMINATION_GRACE
    }
}

fn configured_forced_cleanup_timeout() -> Duration {
    #[cfg(feature = "worker-test-fixtures")]
    {
        Duration::from_millis(FIXTURE_GRACE_MILLIS.load(Ordering::SeqCst))
    }
    #[cfg(not(feature = "worker-test-fixtures"))]
    {
        FORCED_CLEANUP_TIMEOUT
    }
}

fn emit_fixture_event(event: &str) {
    #[cfg(feature = "worker-test-fixtures")]
    crate::full_worker_fixture::emit_fixture_event(event);

    #[cfg(not(feature = "worker-test-fixtures"))]
    let _ = event;
}
