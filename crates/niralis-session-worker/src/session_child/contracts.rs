mod protocol;
pub use protocol::{
    FinalExecFailure, SessionChildCommit, SessionChildCredentialProof, SessionChildEnvelope,
    SessionChildErrorCode, SessionChildIsolationProof, SessionChildResponse,
    SessionChildTerminalContext, SessionChildTerminalProof, SessionChildUnixCredentials,
    SessionProbeHandoff, SessionProcessIdentityProof, SessionRuntimeEnvironmentProof,
    SESSION_CHILD_PROTOCOL_VERSION, SESSION_EXEC_PROBE_VERSION,
};
pub use protocol::{SessionChildRuntimeContext, SessionChildUnixPath};

use std::io::{Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{
    mpsc::{self, Receiver},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::isolation::{
    clear_post_drop_capabilities, validate_isolation_proof_with_allowed_fds, InheritedFdSanitizer,
    LinuxInheritedFdSanitizer, LinuxPostDropAuditor, PostDropAuditor, PostDropIsolationProof,
};
use crate::privilege_drop::{
    AppliedCredentials, LibcPrivilegeDropper, PrivilegeDropError, PrivilegeDropTarget,
    PrivilegeDropper,
};
use protocol::SessionChildRequest;

pub const SESSION_CHILD_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChildExpectation {
    pub canonical_username: String,
    pub session_id: String,
    pub target_credentials: PrivilegeDropTarget,
    pub runtime: SessionChildRuntimeContext,
    pub terminal: Option<SessionChildTerminalContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChildReport {
    pub canonical_username: String,
    pub session_id: String,
    pub child_pid: u32,
    pub applied_credentials: AppliedCredentials,
    pub isolation_proof: PostDropIsolationProof,
    pub process_identity: ProcessIdentityProof,
    pub runtime_environment: RuntimeEnvironmentProof,
    pub exec_probe_version: u32,
    pub credential_proof: SessionChildCredentialProof,
    pub terminal_proof: Option<SessionChildTerminalProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentityProof {
    pub pid: u32,
    pub sid: u32,
    pub pgid: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEnvironmentProof {
    pub home: SessionChildUnixPath,
    pub user: String,
    pub logname: String,
    pub shell: SessionChildUnixPath,
    pub path: String,
    pub session_type: String,
    pub session_class: String,
    pub session_desktop: String,
    pub session_id: String,
    pub runtime_dir: SessionChildUnixPath,
    pub seat: String,
    pub vtnr: u32,
    pub dbus_session_bus_address: Option<String>,
    pub imported_locale: Vec<(String, String)>,
    pub forbidden_variables_present: Vec<String>,
    pub user_bus_connected: bool,
    pub cwd: SessionChildUnixPath,
    pub exec_plan: niralis_session::SessionExecPlan,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SessionChildError {
    #[error("session child path is not absolute")]
    InvalidPath,
    #[error("session child spawn failed")]
    SpawnFailed,
    #[error("session child I/O failed")]
    IoFailed,
    #[error("session child handshake timed out")]
    TimedOut,
    #[error("session child protocol failed")]
    ProtocolFailed,
    #[error("session child exited unsuccessfully")]
    ExitFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionChildWaitEvent {
    Exited(std::process::ExitStatus),
    ControlReady,
}

pub trait SessionChildRunner: Send + Sync {
    fn run_child_until_ready(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<Box<dyn PendingExecHandoff>, SessionChildError>;

    fn run_child(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<SessionChildReport, SessionChildError> {
        self.run_child_until_ready(expectation)?.commit_exec()
    }

    fn wait_for_child(&self) -> Result<std::process::ExitStatus, SessionChildError> {
        Ok(std::process::ExitStatus::from_raw(0))
    }

    fn wait_for_child_or_control(
        &self,
        _control_fd: Option<RawFd>,
    ) -> Result<SessionChildWaitEvent, SessionChildError> {
        self.wait_for_child().map(SessionChildWaitEvent::Exited)
    }

    fn poll_child(&self) -> Result<Option<std::process::ExitStatus>, SessionChildError> {
        Ok(None)
    }

    fn authoritative_pidfd(&self) -> RawFd {
        -1
    }

    fn terminate(&self, _grace: Duration) -> Result<std::process::ExitStatus, SessionChildError> {
        Err(SessionChildError::IoFailed)
    }
}

/// A validated post-exec probe that is still blocked waiting for CommitExec.
/// Consuming it makes duplicate commit impossible. Dropping it aborts and
/// reaps the probe instead of leaving it blocked indefinitely.
pub trait PendingExecHandoff: Send {
    fn report(&self) -> &SessionChildReport;
    fn authoritative_pidfd(&self) -> RawFd;
    fn commit_exec(self: Box<Self>) -> Result<SessionChildReport, SessionChildError>;
    fn abort(self: Box<Self>) -> Result<(), SessionChildError>;
}

pub trait SessionChildRunnerFactory: Send + Sync {
    fn build(&self, path: &Path) -> Result<Box<dyn SessionChildRunner>, SessionChildError>;

    fn build_with_terminal(
        &self,
        path: &Path,
        _terminal_fd: Option<OwnedFd>,
    ) -> Result<Box<dyn SessionChildRunner>, SessionChildError> {
        self.build(path)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessSessionChildRunnerFactory;

impl SessionChildRunnerFactory for ProcessSessionChildRunnerFactory {
    fn build(&self, path: &Path) -> Result<Box<dyn SessionChildRunner>, SessionChildError> {
        Ok(Box::new(ProcessSessionChildRunner::new(
            path.to_path_buf(),
        )?))
    }

    fn build_with_terminal(
        &self,
        path: &Path,
        terminal_fd: Option<OwnedFd>,
    ) -> Result<Box<dyn SessionChildRunner>, SessionChildError> {
        Ok(Box::new(ProcessSessionChildRunner::with_terminal(
            path.to_path_buf(),
            terminal_fd,
        )?))
    }
}

#[derive(Debug, Clone)]
pub struct ProcessSessionChildRunner {
    path: PathBuf,
    terminal_fd: Arc<Mutex<Option<OwnedFd>>>,
    live_child: Arc<Mutex<Option<LiveSessionChild>>>,
}

#[derive(Debug)]
struct LiveSessionChild {
    child: Child,
    pgid: u32,
    pidfd: OwnedFd,
}

struct ProcessPendingExecHandoff {
    attempt: SessionChildAttempt,
    report: SessionChildReport,
    pidfd: Option<OwnedFd>,
    live_child: Arc<Mutex<Option<LiveSessionChild>>>,
    completed: bool,
}
