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

impl PendingExecHandoff for ProcessPendingExecHandoff {
    fn report(&self) -> &SessionChildReport {
        &self.report
    }

    fn authoritative_pidfd(&self) -> RawFd {
        self.pidfd.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }

    fn commit_exec(mut self: Box<Self>) -> Result<SessionChildReport, SessionChildError> {
        let deadline = Instant::now() + SESSION_CHILD_HANDSHAKE_TIMEOUT;
        self.attempt.send_commit(deadline)?;
        match self.attempt.wait_exec_status(deadline)? {
            ExecStatus::Success => {}
            ExecStatus::Failure(failure) => {
                warn!(stage = %failure.stage, errno = failure.errno, "final execve failed");
                return Err(SessionChildError::ExitFailed);
            }
        }
        if self
            .attempt
            .child
            .as_mut()
            .expect("child exists")
            .try_wait()
            .map_err(|_| SessionChildError::IoFailed)?
            .is_some()
        {
            return Err(SessionChildError::ExitFailed);
        }
        let pgid = self.report.process_identity.pgid;
        let pidfd = self.pidfd.take().ok_or(SessionChildError::IoFailed)?;
        let mut live_child = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?;
        let child = self.attempt.take_child();
        *live_child = Some(LiveSessionChild { child, pgid, pidfd });
        self.completed = true;
        Ok(self.report.clone())
    }

    fn abort(mut self: Box<Self>) -> Result<(), SessionChildError> {
        self.attempt.kill_and_reap();
        self.attempt.finish();
        self.completed = true;
        Ok(())
    }
}

impl Drop for ProcessPendingExecHandoff {
    fn drop(&mut self) {
        if !self.completed {
            warn!(
                pid = self.report.child_pid,
                "pending session exec handoff dropped without CommitExec; aborting probe"
            );
        }
        self.attempt.kill_and_reap();
        self.attempt.finish();
    }
}

impl ProcessSessionChildRunner {
    pub fn new(path: PathBuf) -> Result<Self, SessionChildError> {
        if !path.is_absolute() {
            return Err(SessionChildError::InvalidPath);
        }
        Ok(Self {
            path,
            terminal_fd: Arc::new(Mutex::new(None)),
            live_child: Arc::new(Mutex::new(None)),
        })
    }

    pub fn with_terminal(
        path: PathBuf,
        terminal_fd: Option<OwnedFd>,
    ) -> Result<Self, SessionChildError> {
        let runner = Self::new(path)?;
        *runner
            .terminal_fd
            .lock()
            .map_err(|_| SessionChildError::IoFailed)? = terminal_fd;
        Ok(runner)
    }
}

impl Drop for ProcessSessionChildRunner {
    fn drop(&mut self) {
        if let Ok(mut child) = self.live_child.lock() {
            if let Some(mut live) = child.take() {
                let _ = terminate_group(live.pgid, libc::SIGKILL);
                let _ = live.child.wait();
            }
        }
    }
}

impl SessionChildRunner for ProcessSessionChildRunner {
    fn run_child_until_ready(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<Box<dyn PendingExecHandoff>, SessionChildError> {
        let deadline = Instant::now() + SESSION_CHILD_HANDSHAKE_TIMEOUT;
        let request = SessionChildEnvelope {
            version: SESSION_CHILD_PROTOCOL_VERSION,
            message: SessionChildRequest::ApplyCredentials {
                canonical_username: expectation.canonical_username.clone(),
                session_id: expectation.session_id.clone(),
                credentials: SessionChildUnixCredentials::from(&expectation.target_credentials),
                runtime: expectation.runtime.clone(),
                terminal: expectation.terminal.clone(),
            },
        };
        let payload = serde_json::to_vec(&request).map_err(|_| SessionChildError::IoFailed)?;
        if payload.len() + 1 > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
            return Err(SessionChildError::ProtocolFailed);
        }
        let terminal_fd = self
            .terminal_fd
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?
            .take();
        let mut attempt = SessionChildAttempt::spawn(&self.path, payload, terminal_fd)?;
        let pid = attempt.child.as_ref().expect("child exists").id();
        let reader_result = attempt.wait_reader(deadline);
        if let Err(error) = &reader_result {
            match attempt.child.as_mut().expect("child exists").try_wait() {
                Ok(Some(status)) => {
                    warn!(
                        ?error,
                        ?status,
                        "session child exited before sending its ready response"
                    );
                }
                Ok(None) => {
                    warn!(
                        ?error,
                        "session child response read failed while the child remained alive"
                    );
                }
                Err(wait_error) => {
                    warn!(?error, errno = ?wait_error.raw_os_error(), wait_error = %wait_error, "could not inspect session child after its response read failed");
                }
            }
            attempt.kill_and_reap();
        }
        let bytes = reader_result?;
        let response: SessionChildEnvelope<SessionChildResponse> = parse_response(&bytes)?;
        if response.version != SESSION_CHILD_PROTOCOL_VERSION {
            return Err(SessionChildError::ProtocolFailed);
        }
        if let SessionChildResponse::Rejected { code } = &response.message {
            warn!(?code, "session child rejected its credential handoff");
            return Err(SessionChildError::ProtocolFailed);
        }
        let ready_status = attempt
            .child
            .as_mut()
            .expect("child exists")
            .try_wait()
            .map_err(|error| {
                warn!(errno = ?error.raw_os_error(), error = %error, "checking session child state after ready failed");
                SessionChildError::IoFailed
            })?;
        if let Some(status) = ready_status {
            if !status.success() {
                return Err(SessionChildError::ExitFailed);
            }
            return Err(SessionChildError::ExitFailed);
        }
        let report = validate_ready_response(response.message, &expectation, pid, true)?;
        let child = attempt.child.as_ref().expect("child exists");
        let pgid = report.process_identity.pgid;
        let pidfd = match open_pidfd(child.id()) {
            Some(pidfd) => pidfd,
            None => {
                attempt.kill_and_reap();
                return Err(SessionChildError::IoFailed);
            }
        };
        debug_assert_eq!(pgid, report.process_identity.pgid);
        Ok(Box::new(ProcessPendingExecHandoff {
            attempt,
            report,
            pidfd: Some(pidfd),
            live_child: self.live_child.clone(),
            completed: false,
        }))
    }

    fn wait_for_child(&self) -> Result<std::process::ExitStatus, SessionChildError> {
        let mut guard = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?;
        let mut live = guard.take().ok_or(SessionChildError::IoFailed)?;
        live.child.wait().map_err(|_| SessionChildError::IoFailed)
    }

    fn wait_for_child_or_control(
        &self,
        control_fd: Option<RawFd>,
    ) -> Result<SessionChildWaitEvent, SessionChildError> {
        let mut guard = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?;
        let live = guard.as_mut().ok_or(SessionChildError::IoFailed)?;
        let mut fds = [
            libc::pollfd {
                fd: live.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: control_fd.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let count = if control_fd.is_some() { 2 } else { 1 };
        let result = unsafe { libc::poll(fds.as_mut_ptr(), count, -1) };
        if result < 0 {
            return Err(SessionChildError::IoFailed);
        }
        if control_fd.is_some() && fds[1].revents & libc::POLLIN != 0 {
            return Ok(SessionChildWaitEvent::ControlReady);
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) == 0 {
            return Err(SessionChildError::IoFailed);
        }
        let mut live = guard.take().ok_or(SessionChildError::IoFailed)?;
        live.child
            .wait()
            .map(SessionChildWaitEvent::Exited)
            .map_err(|_| SessionChildError::IoFailed)
    }

    fn poll_child(&self) -> Result<Option<std::process::ExitStatus>, SessionChildError> {
        let mut guard = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?;
        let Some(live) = guard.as_mut() else {
            return Err(SessionChildError::IoFailed);
        };
        match live
            .child
            .try_wait()
            .map_err(|_| SessionChildError::IoFailed)?
        {
            Some(status) => {
                guard.take();
                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    fn terminate(&self, grace: Duration) -> Result<std::process::ExitStatus, SessionChildError> {
        let mut live = self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?
            .take()
            .ok_or(SessionChildError::IoFailed)?;
        let _ = terminate_group(live.pgid, libc::SIGTERM);
        info!(pgid = live.pgid, "session process group SIGTERM sent");
        let deadline = Instant::now() + grace;
        loop {
            if let Some(status) = live
                .child
                .try_wait()
                .map_err(|_| SessionChildError::IoFailed)?
            {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                info!(pgid = live.pgid, "session termination grace period expired");
                terminate_group(live.pgid, libc::SIGKILL)?;
                info!(pgid = live.pgid, "session process group SIGKILL sent");
                return live.child.wait().map_err(|_| SessionChildError::IoFailed);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn terminate_group(pgid: u32, signal: libc::c_int) -> Result<(), SessionChildError> {
    if pgid == 0 || pgid > libc::pid_t::MAX as u32 {
        return Err(SessionChildError::IoFailed);
    }
    let result = unsafe { libc::kill(-(pgid as libc::pid_t), signal) };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(SessionChildError::IoFailed)
    }
}

fn open_pidfd(pid: u32) -> Option<OwnedFd> {
    if pid == 0 || pid > libc::pid_t::MAX as u32 {
        return None;
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        None
    } else {
        Some(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }
}

fn validate_ready_response(
    response: SessionChildResponse,
    expectation: &SessionChildExpectation,
    pid: u32,
    allows_status_pipe: bool,
) -> Result<SessionChildReport, SessionChildError> {
    let mut allowed_inherited_fds = expectation
        .terminal
        .as_ref()
        .map_or_else(Vec::new, |terminal| vec![terminal.fd]);
    if allows_status_pipe {
        allowed_inherited_fds.push(4);
    }
    match response {
        SessionChildResponse::Ready {
            canonical_username,
            session_id,
            child_pid,
            applied_credentials,
            credential_proof,
            isolation_proof,
            process_identity,
            runtime_environment,
            exec_probe_version,
            terminal_proof,
        } if canonical_username == expectation.canonical_username
            && session_id == expectation.session_id
            && child_pid == pid
            && applied_credentials
                == SessionChildUnixCredentials::from(&expectation.target_credentials)
            && {
                let proof = PostDropIsolationProof::from(isolation_proof.clone());
                let present_allowed_fds = allowed_inherited_fds
                    .iter()
                    .copied()
                    .filter(|fd| proof.open_fds.binary_search(fd).is_ok())
                    .collect::<Vec<_>>();
                validate_isolation_proof_with_allowed_fds(&proof, &present_allowed_fds).is_ok()
            }
            && credential_proof.real_uid == expectation.target_credentials.uid
            && credential_proof.effective_uid == expectation.target_credentials.uid
            && credential_proof.saved_uid == expectation.target_credentials.uid
            && credential_proof.real_gid == expectation.target_credentials.gid
            && credential_proof.effective_gid == expectation.target_credentials.gid
            && credential_proof.saved_gid == expectation.target_credentials.gid
            && normalized_groups(
                credential_proof.supplementary_gids.clone(),
                expectation.target_credentials.gid,
            ) == expectation.target_credentials.supplementary_gids
            && exec_probe_version == SESSION_EXEC_PROBE_VERSION
            && process_identity.pid == pid
            && process_identity.sid == pid
            && process_identity.pgid == pid
            && runtime_environment.home == expectation.runtime.home
            && runtime_environment.shell == expectation.runtime.shell
            && runtime_environment.session_type == expectation.runtime.session_type
            && (expectation.runtime.session_id.is_empty()
                || (runtime_environment.session_class == expectation.runtime.session_class
                    && runtime_environment.session_desktop
                        == expectation.runtime.session_desktop
                    && runtime_environment.session_id == expectation.runtime.session_id
                    && runtime_environment.runtime_dir == expectation.runtime.runtime_dir
                    && runtime_environment.seat == expectation.runtime.seat
                    && runtime_environment.vtnr == expectation.runtime.vtnr
                    && runtime_environment.dbus_session_bus_address
                        == expectation.runtime.dbus_session_bus_address
                    && runtime_environment.imported_locale
                        == expectation.runtime.imported_locale
                    && runtime_environment.forbidden_variables_present.is_empty()
                    && runtime_environment.user_bus_connected))
            && runtime_environment.user == expectation.canonical_username
            && runtime_environment.logname == expectation.canonical_username
            && runtime_environment.path == DEFAULT_SESSION_PATH
            && runtime_environment.cwd == expectation.runtime.home
            && (expectation.runtime.session_id.is_empty()
                || runtime_environment.exec_plan == expectation.runtime.exec_plan)
            && match (&expectation.terminal, &terminal_proof) {
                (None, None) => true,
                (Some(expected), Some(actual)) => {
                    actual.seat == expected.seat
                        && actual.vtnr == expected.vtnr
                        && actual.fd == expected.fd
                        && actual.device_major == expected.device_major
                        && actual.device_minor == expected.device_minor
                        && actual.controlling_sid == pid
                        && actual.foreground_pgid == pid
                }
                _ => false,
            } =>
        {
            Ok(SessionChildReport {
                canonical_username,
                session_id,
                child_pid,
                applied_credentials: AppliedCredentials {
                    uid: applied_credentials.uid,
                    gid: applied_credentials.gid,
                    supplementary_gids: applied_credentials.supplementary_gids,
                },
                isolation_proof: isolation_proof.into(),
                process_identity: ProcessIdentityProof {
                    pid: process_identity.pid,
                    sid: process_identity.sid,
                    pgid: process_identity.pgid,
                },
                runtime_environment: RuntimeEnvironmentProof {
                    home: runtime_environment.home,
                    user: runtime_environment.user,
                    logname: runtime_environment.logname,
                    shell: runtime_environment.shell,
                    path: runtime_environment.path,
                    session_type: runtime_environment.session_type,
                    session_class: runtime_environment.session_class,
                    session_desktop: runtime_environment.session_desktop,
                    session_id: runtime_environment.session_id,
                    runtime_dir: runtime_environment.runtime_dir,
                    seat: runtime_environment.seat,
                    vtnr: runtime_environment.vtnr,
                    dbus_session_bus_address: runtime_environment.dbus_session_bus_address,
                    imported_locale: runtime_environment.imported_locale,
                    forbidden_variables_present: runtime_environment.forbidden_variables_present,
                    user_bus_connected: runtime_environment.user_bus_connected,
                    cwd: runtime_environment.cwd,
                    exec_plan: runtime_environment.exec_plan,
                },
                exec_probe_version,
                credential_proof,
                terminal_proof,
            })
        }
        SessionChildResponse::Rejected { .. } => Err(SessionChildError::ProtocolFailed),
        SessionChildResponse::Ready {
            canonical_username,
            session_id,
            child_pid,
            applied_credentials,
            credential_proof,
            isolation_proof,
            process_identity,
            runtime_environment,
            exec_probe_version,
            terminal_proof,
        } => {
            let proof = PostDropIsolationProof::from(isolation_proof.clone());
            let present_allowed_fds = allowed_inherited_fds
                .iter()
                .copied()
                .filter(|fd| proof.open_fds.binary_search(fd).is_ok())
                .collect::<Vec<_>>();
            let credential_proof_matches = credential_proof.real_uid
                == expectation.target_credentials.uid
                && credential_proof.effective_uid == expectation.target_credentials.uid
                && credential_proof.saved_uid == expectation.target_credentials.uid
                && credential_proof.real_gid == expectation.target_credentials.gid
                && credential_proof.effective_gid == expectation.target_credentials.gid
                && credential_proof.saved_gid == expectation.target_credentials.gid
                && normalized_groups(
                    credential_proof.supplementary_gids,
                    expectation.target_credentials.gid,
                ) == expectation.target_credentials.supplementary_gids;
            let terminal_proof_matches = match (&expectation.terminal, &terminal_proof) {
                (None, None) => true,
                (Some(expected), Some(actual)) => {
                    actual.seat == expected.seat
                        && actual.vtnr == expected.vtnr
                        && actual.fd == expected.fd
                        && actual.device_major == expected.device_major
                        && actual.device_minor == expected.device_minor
                        && actual.controlling_sid == pid
                        && actual.foreground_pgid == pid
                }
                _ => false,
            };
            warn!(
                canonical_username_matches = canonical_username == expectation.canonical_username,
                session_id_matches = session_id == expectation.session_id,
                child_pid_matches = child_pid == pid,
                applied_credentials_match = applied_credentials
                    == SessionChildUnixCredentials::from(&expectation.target_credentials),
                credential_proof_matches,
                isolation_proof_valid =
                    validate_isolation_proof_with_allowed_fds(&proof, &present_allowed_fds).is_ok(),
                process_identity_matches = process_identity.pid == pid
                    && process_identity.sid == pid
                    && process_identity.pgid == pid,
                exec_probe_version_matches = exec_probe_version == SESSION_EXEC_PROBE_VERSION,
                runtime_user_matches = runtime_environment.user == expectation.canonical_username
                    && runtime_environment.logname == expectation.canonical_username,
                runtime_path_matches = runtime_environment.path == DEFAULT_SESSION_PATH,
                runtime_cwd_matches = runtime_environment.cwd == expectation.runtime.home,
                terminal_proof_matches,
                "session child Ready response failed strict validation"
            );
            Err(SessionChildError::ProtocolFailed)
        }
    }
}

fn normalized_groups(mut groups: Vec<u32>, primary_gid: u32) -> Vec<u32> {
    groups.sort_unstable();
    groups.dedup();
    groups.retain(|gid| *gid != primary_gid);
    groups
}

pub const DEFAULT_SESSION_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

struct SessionChildAttempt {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    reader: Option<JoinHandle<()>>,
    response_rx: Receiver<Result<Vec<u8>, SessionChildError>>,
    status_read: Option<OwnedFd>,
}

impl SessionChildAttempt {
    fn take_child(&mut self) -> Child {
        self.child.take().expect("child exists")
    }
}

impl SessionChildAttempt {
    fn spawn(
        path: &Path,
        payload: Vec<u8>,
        terminal_fd: Option<OwnedFd>,
    ) -> Result<Self, SessionChildError> {
        let mut command = Command::new(path);
        let (status_read, status_write) = make_status_pipe()?;
        let status_raw = status_write.as_raw_fd();
        let terminal_source_fd = terminal_fd.as_ref().map(AsRawFd::as_raw_fd);
        let fd_mapping_collision = terminal_source_fd == Some(4) || status_raw == 3;
        tracing::debug!(
            status_source_fd = status_raw,
            status_target_fd = 4,
            terminal_source_fd = ?terminal_source_fd,
            terminal_target_fd = 3,
            fd_mapping_collision,
            "prepared session child fd mapping"
        );
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(move || {
                if libc::dup2(status_raw, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let terminal_fd_keepalive = terminal_fd;
        if let Some(terminal_fd) = terminal_fd_keepalive.as_ref() {
            let source_fd = std::os::fd::AsRawFd::as_raw_fd(terminal_fd);
            unsafe {
                use std::os::unix::process::CommandExt;
                command.pre_exec(move || {
                    if libc::dup2(source_fd, 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env_clear()
            .current_dir("/")
            .spawn()
            .map_err(|error| {
                warn!(
                    path = %path.display(),
                    errno = ?error.raw_os_error(),
                    kind = ?error.kind(),
                    error = %error,
                    status_source_fd = status_raw,
                    terminal_source_fd = ?terminal_source_fd,
                    fd_mapping_collision,
                    "failed to spawn session child"
                );
                SessionChildError::SpawnFailed
            })?;
        let mut child = child;
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                warn!("session child did not provide stdin for the private request");
                kill_and_reap(&mut child);
                return Err(SessionChildError::IoFailed);
            }
        };
        let mut stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                warn!("session child did not provide stdout for the private response");
                kill_and_reap(&mut child);
                return Err(SessionChildError::IoFailed);
            }
        };
        let mut stdin = stdin;
        stdin
            .write_all(&payload)
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|error| {
                warn!(
                    errno = ?error.raw_os_error(),
                    error = %error,
                    request_bytes = payload.len(),
                    "writing the private session-child request failed"
                );
                SessionChildError::IoFailed
            })?;
        let (response_tx, response_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let _ = response_tx.send(read_child_response(&mut stdout));
        });
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            reader: Some(reader),
            response_rx,
            status_read: Some(status_read),
        })
    }

    fn wait_reader(&self, deadline: Instant) -> Result<Vec<u8>, SessionChildError> {
        wait_result(&self.response_rx, deadline)
    }

    fn send_commit(&mut self, _deadline: Instant) -> Result<(), SessionChildError> {
        let mut stdin = self.stdin.take().ok_or(SessionChildError::IoFailed)?;
        let message = SessionChildEnvelope {
            version: SESSION_CHILD_PROTOCOL_VERSION,
            message: SessionChildCommit::Exec,
        };
        serde_json::to_writer(&mut stdin, &message).map_err(|error| {
            warn!(error = %error, "serializing CommitExec for the session child failed");
            SessionChildError::IoFailed
        })?;
        stdin
            .write_all(b"\n")
            .map_err(|error| {
                warn!(errno = ?error.raw_os_error(), error = %error, "writing CommitExec to the session child failed");
                SessionChildError::IoFailed
            })?;
        stdin.flush().map_err(|error| {
            warn!(errno = ?error.raw_os_error(), error = %error, "flushing CommitExec to the session child failed");
            SessionChildError::IoFailed
        })
    }

    fn wait_exec_status(&mut self, deadline: Instant) -> Result<ExecStatus, SessionChildError> {
        let fd = self.status_read.take().ok_or(SessionChildError::IoFailed)?;
        let timeout = remaining(deadline)?;
        read_exec_status(fd, timeout)
    }

    fn kill_and_reap(&mut self) {
        if let Some(child) = self.child.as_mut() {
            kill_and_reap(child);
        }
    }

    fn finish(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn make_status_pipe() -> Result<(OwnedFd, OwnedFd), SessionChildError> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SessionChildError::IoFailed);
    }
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

enum ExecStatus {
    Success,
    Failure(FinalExecFailure),
}

fn read_exec_status(fd: OwnedFd, timeout: Duration) -> Result<ExecStatus, SessionChildError> {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
    let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
    if ready == 0 {
        warn!(
            timeout_ms = millis,
            "timed out waiting for the session child exec status pipe"
        );
        return Err(SessionChildError::TimedOut);
    }
    if ready < 0 {
        warn!(
            errno = ?std::io::Error::last_os_error().raw_os_error(),
            "polling the session child exec status pipe failed"
        );
        return Err(SessionChildError::IoFailed);
    }
    if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        warn!(
            revents = pollfd.revents,
            "session child exec status pipe reported an error"
        );
        return Err(SessionChildError::IoFailed);
    }
    let mut payload = [0_u8; 512];
    let count = unsafe { libc::read(fd.as_raw_fd(), payload.as_mut_ptr().cast(), payload.len()) };
    if count == 0 {
        return Ok(ExecStatus::Success);
    }
    if count < 0 {
        warn!(
            errno = ?std::io::Error::last_os_error().raw_os_error(),
            "reading the session child exec status pipe failed"
        );
        return Err(SessionChildError::IoFailed);
    }
    let failure = serde_json::from_slice::<FinalExecFailure>(&payload[..count as usize])
        .map_err(|_| SessionChildError::ProtocolFailed)?;
    Ok(ExecStatus::Failure(failure))
}

impl Drop for SessionChildAttempt {
    fn drop(&mut self) {
        self.kill_and_reap();
        self.finish();
    }
}

fn remaining(deadline: Instant) -> Result<Duration, SessionChildError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or(SessionChildError::TimedOut)
}

fn wait_result<T: Send + 'static>(
    receiver: &Receiver<Result<T, SessionChildError>>,
    deadline: Instant,
) -> Result<T, SessionChildError> {
    let timeout = remaining(deadline)?;
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            warn!("timed out waiting for a private session-child message");
            Err(SessionChildError::TimedOut)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            warn!("private session-child response channel disconnected");
            Err(SessionChildError::IoFailed)
        }
    }
}

fn read_child_response(reader: &mut impl Read) -> Result<Vec<u8>, SessionChildError> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte).map_err(|error| {
            warn!(
                errno = ?error.raw_os_error(),
                error = %error,
                received_bytes = bytes.len(),
                "reading a private session-child message failed"
            );
            SessionChildError::IoFailed
        })?;
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
            return Err(SessionChildError::ProtocolFailed);
        }
    }
    if bytes.is_empty() || bytes.len() > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
        return Err(SessionChildError::ProtocolFailed);
    }
    Ok(bytes)
}

fn parse_response(
    bytes: &[u8],
) -> Result<SessionChildEnvelope<SessionChildResponse>, SessionChildError> {
    if !bytes.ends_with(b"\n") {
        return Err(SessionChildError::ProtocolFailed);
    }
    let line = &bytes[..bytes.len() - 1];
    if line.is_empty() || line.contains(&b'\n') {
        return Err(SessionChildError::ProtocolFailed);
    }
    serde_json::from_slice(line).map_err(|_| SessionChildError::ProtocolFailed)
}

fn kill_and_reap(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) | Err(_) => {}
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn run_child_process() -> i32 {
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    run_child_process_with_dependencies(
        stdin,
        stdout,
        &LibcPrivilegeDropper,
        &LinuxInheritedFdSanitizer,
        &LinuxPostDropAuditor,
        std::process::id(),
    )
}

#[cfg(test)]
pub(crate) fn run_child_process_with_dropper(
    reader: impl Read,
    writer: impl Write,
    dropper: &impl PrivilegeDropper,
    child_pid: u32,
) -> i32 {
    run_child_process_with_dependencies(
        reader,
        writer,
        dropper,
        &NoopFdSanitizer,
        &StubAudit,
        child_pid,
    )
}

pub(crate) fn run_child_process_with_dependencies(
    mut reader: impl Read,
    mut writer: impl Write,
    dropper: &impl PrivilegeDropper,
    fd_sanitizer: &impl InheritedFdSanitizer,
    auditor: &impl PostDropAuditor,
    child_pid: u32,
) -> i32 {
    let bytes = match read_child_response(&mut reader) {
        Ok(bytes) => bytes,
        Err(_) => return 1,
    };
    let request: SessionChildEnvelope<SessionChildRequest> = match parse_request(&bytes) {
        Ok(request) => request,
        Err(code) => {
            let _ = write_rejection(&mut writer, code);
            return 1;
        }
    };
    if request.version != SESSION_CHILD_PROTOCOL_VERSION {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::UnsupportedVersion);
        return 1;
    }
    let SessionChildRequest::ApplyCredentials {
        canonical_username,
        session_id,
        credentials,
        runtime,
        terminal,
    } = request.message;
    if credentials.uid == 0 {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::RootUidDisallowed);
        return 1;
    }
    let mut allowed_inherited_fds = terminal
        .as_ref()
        .map_or_else(Vec::new, |value| vec![value.fd]);
    // FD 4 is the parent's CLOEXEC status pipe.  It is needed until the
    // commit/exec handoff completes, then is closed automatically by execve.
    if child_pid == std::process::id() {
        allowed_inherited_fds.push(4);
    }
    if fd_sanitizer
        .sanitize_with_allowlist(&allowed_inherited_fds)
        .is_err()
    {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::FdSanitizationFailed);
        return 1;
    }
    let target = PrivilegeDropTarget::from(credentials);
    let applied = match dropper.drop_privileges(&target) {
        Ok(applied) => applied,
        Err(PrivilegeDropError::RootUidDisallowed) => {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::RootUidDisallowed);
            return 1;
        }
        Err(error) => {
            eprintln!("session child privilege drop failed error={error}");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::PrivilegeDropFailed);
            return 1;
        }
    };
    let applied_credentials = SessionChildUnixCredentials::from(&applied);
    if applied_credentials != SessionChildUnixCredentials::from(&target) {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::CredentialMismatch);
        return 1;
    }
    if child_pid == std::process::id() && clear_post_drop_capabilities().is_err() {
        eprintln!("session child post-drop capability sanitization failed");
        let _ = write_rejection(&mut writer, SessionChildErrorCode::IsolationAuditFailed);
        return 1;
    }
    let proof = match auditor.audit() {
        Ok(proof) => proof,
        Err(_) => {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::IsolationAuditFailed);
            return 1;
        }
    };
    if let Err(error) = validate_isolation_proof_with_allowed_fds(&proof, &allowed_inherited_fds) {
        eprintln!(
            "session child isolation policy failed error={error} effective_capability_count={} permitted_capability_count={} inheritable_capability_count={} inheritable_capabilities={:?} ambient_capability_count={} bounding_capability_count={} securebits={} no_new_privs={} open_fds={:?} allowed_inherited_fds={allowed_inherited_fds:?}",
            proof.capabilities.effective.len(),
            proof.capabilities.permitted.len(),
            proof.capabilities.inheritable.len(),
            proof.capabilities.inheritable,
            proof.capabilities.ambient.len(),
            proof.capabilities.bounding.len(),
            proof.securebits,
            proof.no_new_privs,
            proof.open_fds,
        );
        let _ = write_rejection(&mut writer, SessionChildErrorCode::IsolationPolicyFailed);
        return 1;
    }
    // The production child replaces itself with the trusted probe. Test seams use
    // synthetic PIDs and retain the response path for deterministic unit tests.
    let terminal_proof = if child_pid == std::process::id() {
        if unsafe { libc::setsid() } < 0 {
            eprintln!("session child terminal setup failed stage=setsid");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::SessionBoundaryFailed);
            return 1;
        }
        let terminal = match terminal.as_ref() {
            Some(terminal) if terminal.fd == 3 => terminal,
            _ => {
                eprintln!("session child terminal setup failed stage=terminal_fd");
                let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
                return 1;
            }
        };
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(terminal.fd, &mut stat) } < 0
            || libc::major(stat.st_rdev) as u32 != terminal.device_major
            || libc::minor(stat.st_rdev) as u32 != terminal.device_minor
        {
            eprintln!("session child terminal setup failed stage=fstat");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        if unsafe { libc::ioctl(terminal.fd, libc::TIOCSCTTY, 0) } < 0 {
            eprintln!("session child terminal setup failed stage=tiocsctty");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        let previous_sigttou = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
        let foreground = unsafe { libc::tcsetpgrp(terminal.fd, libc::getpgrp()) };
        unsafe { libc::signal(libc::SIGTTOU, previous_sigttou) };
        if foreground != 0 {
            eprintln!("session child terminal setup failed stage=tcsetpgrp");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        let sid = unsafe { libc::tcgetsid(terminal.fd) };
        let pgid = unsafe { libc::tcgetpgrp(terminal.fd) };
        let pid = unsafe { libc::getpid() };
        if sid <= 0 || pgid <= 0 || sid as u32 != pid as u32 || pgid as u32 != pid as u32 {
            eprintln!("session child terminal setup failed stage=terminal_identity");
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        Some(SessionChildTerminalProof {
            seat: terminal.seat.clone(),
            vtnr: terminal.vtnr,
            fd: terminal.fd,
            device_major: terminal.device_major,
            device_minor: terminal.device_minor,
            controlling_sid: sid as u32,
            foreground_pgid: pgid as u32,
        })
    } else {
        None
    };
    if child_pid == std::process::id() {
        let home = match runtime.home.to_path_buf() {
            Ok(path) if path.is_absolute() => path,
            _ => {
                let _ =
                    write_rejection(&mut writer, SessionChildErrorCode::HomeDirectoryUnavailable);
                return 1;
            }
        };
        if std::env::set_current_dir(&home).is_err() {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::HomeDirectoryUnavailable);
            return 1;
        }
        if install_runtime_environment(&runtime, &canonical_username).is_err() {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::InvalidRuntimeContext);
            return 1;
        }
        if crate::prove_user_bus().is_err() {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::RuntimeProbeFailed);
            return 1;
        }
    }
    // The real child must not claim readiness before the post-exec probe has
    // re-audited the process. Unit-only callers pass a synthetic PID and keep
    // the response construction below as a narrow seam for child-core tests.
    if child_pid == std::process::id() {
        if exec_probe(
            &runtime,
            &canonical_username,
            &session_id,
            terminal.as_ref(),
        )
        .is_err()
        {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::ExecFailed);
        }
        return 1;
    }

    let response = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildResponse::Ready {
            canonical_username: canonical_username.clone(),
            session_id,
            child_pid,
            applied_credentials: applied_credentials.clone(),
            credential_proof: SessionChildCredentialProof {
                real_uid: applied_credentials.uid,
                effective_uid: applied_credentials.uid,
                saved_uid: applied_credentials.uid,
                real_gid: applied_credentials.gid,
                effective_gid: applied_credentials.gid,
                saved_gid: applied_credentials.gid,
                supplementary_gids: applied_credentials.supplementary_gids.clone(),
            },
            isolation_proof: SessionChildIsolationProof::from(&proof),
            process_identity: SessionProcessIdentityProof {
                pid: child_pid,
                sid: child_pid,
                pgid: child_pid,
            },
            runtime_environment: SessionRuntimeEnvironmentProof {
                home: runtime.home.clone(),
                user: canonical_username.clone(),
                logname: canonical_username.clone(),
                shell: runtime.shell.clone(),
                path: DEFAULT_SESSION_PATH.to_owned(),
                session_type: runtime.session_type.clone(),
                session_class: runtime.session_class.clone(),
                session_desktop: runtime.session_desktop.clone(),
                session_id: runtime.session_id.clone(),
                runtime_dir: runtime.runtime_dir.clone(),
                seat: runtime.seat.clone(),
                vtnr: runtime.vtnr,
                dbus_session_bus_address: runtime.dbus_session_bus_address.clone(),
                imported_locale: runtime.imported_locale.clone(),
                forbidden_variables_present: Vec::new(),
                user_bus_connected: true,
                cwd: runtime.home,
                exec_plan: runtime.exec_plan.clone(),
            },
            exec_probe_version: SESSION_EXEC_PROBE_VERSION,
            terminal_proof,
        },
    };
    if let Err(error) = serde_json::to_writer(&mut writer, &response) {
        eprintln!("session child ready response failed stage=serialize error={error}");
        return 1;
    }
    if let Err(error) = writer.write_all(b"\n") {
        eprintln!(
            "session child ready response failed stage=write errno={:?} error={error}",
            error.raw_os_error()
        );
        return 1;
    }
    if let Err(error) = writer.flush() {
        eprintln!(
            "session child ready response failed stage=flush errno={:?} error={error}",
            error.raw_os_error()
        );
        return 1;
    }
    0
}

fn install_runtime_environment(
    runtime: &SessionChildRuntimeContext,
    username: &str,
) -> Result<(), ()> {
    unsafe {
        libc::clearenv();
    }
    let mut entries = vec![
        (
            "HOME".to_owned(),
            runtime.home.to_path_buf().map_err(|_| ())?,
        ),
        ("USER".to_owned(), std::path::PathBuf::from(username)),
        ("LOGNAME".to_owned(), std::path::PathBuf::from(username)),
        (
            "SHELL".to_owned(),
            runtime.shell.to_path_buf().map_err(|_| ())?,
        ),
        (
            "PATH".to_owned(),
            std::path::PathBuf::from(DEFAULT_SESSION_PATH),
        ),
        (
            "XDG_SESSION_TYPE".to_owned(),
            std::path::PathBuf::from(&runtime.session_type),
        ),
        (
            "XDG_SESSION_CLASS".to_owned(),
            std::path::PathBuf::from(&runtime.session_class),
        ),
        (
            "XDG_SESSION_DESKTOP".to_owned(),
            std::path::PathBuf::from(&runtime.session_desktop),
        ),
        (
            "XDG_SESSION_ID".to_owned(),
            std::path::PathBuf::from(&runtime.session_id),
        ),
        (
            "XDG_RUNTIME_DIR".to_owned(),
            runtime.runtime_dir.to_path_buf().map_err(|_| ())?,
        ),
        (
            "XDG_SEAT".to_owned(),
            std::path::PathBuf::from(&runtime.seat),
        ),
        (
            "XDG_VTNR".to_owned(),
            std::path::PathBuf::from(runtime.vtnr.to_string()),
        ),
    ];
    if let Some(address) = &runtime.dbus_session_bus_address {
        entries.push((
            "DBUS_SESSION_BUS_ADDRESS".to_owned(),
            std::path::PathBuf::from(address),
        ));
    }
    for (key, value) in &runtime.imported_locale {
        entries.push((key.clone(), std::path::PathBuf::from(value)));
    }
    use std::os::unix::ffi::OsStrExt;
    for (key, value) in entries {
        let key = std::ffi::CString::new(key).map_err(|_| ())?;
        let value = std::ffi::CString::new(value.as_os_str().as_bytes()).map_err(|_| ())?;
        if unsafe { libc::setenv(key.as_ptr(), value.as_ptr(), 1) } != 0 {
            return Err(());
        }
    }
    Ok(())
}

const PROBE_HANDOFF_FD: libc::c_int = 5;

fn exec_probe(
    runtime: &SessionChildRuntimeContext,
    username: &str,
    session_id: &str,
    terminal: Option<&SessionChildTerminalContext>,
) -> Result<(), ()> {
    let probe = runtime.probe_path.to_path_buf().map_err(|_| ())?;
    if !probe.is_absolute() {
        return Err(());
    }
    let handoff = SessionProbeHandoff {
        exec_plan: runtime.exec_plan.clone(),
        selinux_exec_context: runtime.selinux_exec_context.clone(),
    };
    let payload = serde_json::to_vec(&handoff).map_err(|_| ())?;
    if payload.is_empty() || payload.len() > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
        return Err(());
    }
    let name = std::ffi::CString::new("niralis-probe-handoff").map_err(|_| ())?;
    let handoff_fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC) };
    if handoff_fd < 0 {
        return Err(());
    }
    let result = (|| {
        let mut file = unsafe { std::fs::File::from_raw_fd(handoff_fd) };
        file.write_all(&payload).map_err(|_| ())?;
        file.sync_all().map_err(|_| ())?;
        if file.rewind().is_err() {
            return Err(());
        }
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(());
        }
        let source = file.into_raw_fd();
        if unsafe { libc::dup2(source, PROBE_HANDOFF_FD) } < 0 {
            unsafe { libc::close(source) };
            return Err(());
        }
        if source != PROBE_HANDOFF_FD {
            unsafe { libc::close(source) };
        }
        if unsafe { libc::fcntl(PROBE_HANDOFF_FD, libc::F_SETFD, 0) } < 0 {
            return Err(());
        }
        Ok(())
    })();
    result?;

    let mut command = Command::new(probe);
    command.arg(username).arg(session_id);
    if let Some(terminal) = terminal {
        command
            .arg("--terminal-seat")
            .arg(&terminal.seat)
            .arg("--terminal-vtnr")
            .arg(terminal.vtnr.to_string())
            .arg("--terminal-major")
            .arg(terminal.device_major.to_string())
            .arg("--terminal-minor")
            .arg(terminal.device_minor.to_string());
    }
    let _ = std::os::unix::process::CommandExt::exec(&mut command);
    Err(())
}

#[cfg(test)]
struct NoopFdSanitizer;
#[cfg(test)]
impl InheritedFdSanitizer for NoopFdSanitizer {
    fn sanitize(&self) -> Result<(), crate::isolation::FdSanitizationError> {
        Ok(())
    }
}

#[cfg(test)]
struct StubAudit;
#[cfg(test)]
impl PostDropAuditor for StubAudit {
    fn audit(&self) -> Result<PostDropIsolationProof, crate::isolation::PostDropAuditError> {
        Ok(PostDropIsolationProof {
            capabilities: crate::isolation::CapabilityState {
                effective: vec![],
                permitted: vec![],
                inheritable: vec![],
                ambient: vec![],
                bounding: vec![],
                cap_last_cap: 0,
            },
            securebits: 0,
            no_new_privs: false,
            open_fds: vec![0, 1, 2],
        })
    }
}

fn parse_request(
    bytes: &[u8],
) -> Result<SessionChildEnvelope<SessionChildRequest>, SessionChildErrorCode> {
    if bytes.is_empty()
        || bytes.len() > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES
        || !bytes.ends_with(b"\n")
    {
        return Err(SessionChildErrorCode::InvalidRequest);
    }
    serde_json::from_slice(&bytes[..bytes.len() - 1])
        .map_err(|_| SessionChildErrorCode::InvalidRequest)
}

fn write_rejection(writer: &mut impl Write, code: SessionChildErrorCode) -> std::io::Result<()> {
    let response = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildResponse::Rejected { code },
    };
    serde_json::to_writer(&mut *writer, &response)?;
    writer.write_all(b"\n")
}

#[cfg(test)]
mod tests;
