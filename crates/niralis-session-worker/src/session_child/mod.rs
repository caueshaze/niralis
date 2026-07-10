mod protocol;
pub use protocol::{
    SessionChildCredentialProof, SessionChildEnvelope, SessionChildErrorCode,
    SessionChildIsolationProof, SessionChildResponse, SessionChildTerminalContext,
    SessionChildTerminalProof, SessionChildUnixCredentials, SessionProcessIdentityProof,
    SessionRuntimeEnvironmentProof, SESSION_CHILD_PROTOCOL_VERSION, SESSION_EXEC_PROBE_VERSION,
};
pub use protocol::{SessionChildRuntimeContext, SessionChildUnixPath};

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    mpsc::{self, Receiver},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tracing::info;

use crate::isolation::{
    validate_isolation_proof, validate_isolation_proof_with_allowed_fds, InheritedFdSanitizer,
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
    pub cwd: SessionChildUnixPath,
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

pub trait SessionChildRunner: Send + Sync {
    fn run_child(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<SessionChildReport, SessionChildError>;

    fn wait_for_child(&self) -> Result<std::process::ExitStatus, SessionChildError> {
        Ok(std::process::ExitStatus::from_raw(0))
    }

    fn poll_child(&self) -> Result<Option<std::process::ExitStatus>, SessionChildError> {
        Ok(None)
    }

    fn terminate(&self, _grace: Duration) -> Result<std::process::ExitStatus, SessionChildError> {
        Err(SessionChildError::IoFailed)
    }
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
    fn run_child(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<SessionChildReport, SessionChildError> {
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
        let writer_result = attempt.wait_writer(deadline);
        let reader_result = match &writer_result {
            Ok(()) => attempt.wait_reader(deadline),
            Err(error) => Err(error.clone()),
        };
        let needs_cleanup = writer_result.is_err() || reader_result.is_err();
        if needs_cleanup {
            attempt.kill_and_reap();
        }
        attempt.finish();
        writer_result?;
        let bytes = reader_result?;
        let response: SessionChildEnvelope<SessionChildResponse> = parse_response(&bytes)?;
        if response.version != SESSION_CHILD_PROTOCOL_VERSION {
            return Err(SessionChildError::ProtocolFailed);
        }
        if let Some(status) = attempt
            .child
            .as_mut()
            .expect("child exists")
            .try_wait()
            .map_err(|_| SessionChildError::IoFailed)?
        {
            if !status.success() {
                return Err(SessionChildError::ExitFailed);
            }
            return Err(SessionChildError::ExitFailed);
        }
        let report = validate_ready_response(response.message, &expectation, pid)?;
        let child = attempt.take_child();
        let pgid = report.process_identity.pgid;
        *self
            .live_child
            .lock()
            .map_err(|_| SessionChildError::IoFailed)? = Some(LiveSessionChild { child, pgid });
        Ok(report)
    }

    fn wait_for_child(&self) -> Result<std::process::ExitStatus, SessionChildError> {
        loop {
            if let Some(status) = self.poll_child()? {
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(25));
        }
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

fn validate_ready_response(
    response: SessionChildResponse,
    expectation: &SessionChildExpectation,
    pid: u32,
) -> Result<SessionChildReport, SessionChildError> {
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
            && validate_isolation_proof(&PostDropIsolationProof::from(isolation_proof.clone()))
                .is_ok()
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
            && runtime_environment.user == expectation.canonical_username
            && runtime_environment.logname == expectation.canonical_username
            && runtime_environment.path == DEFAULT_SESSION_PATH
            && runtime_environment.cwd == expectation.runtime.home
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
                    cwd: runtime_environment.cwd,
                },
                exec_probe_version,
                credential_proof,
                terminal_proof,
            })
        }
        SessionChildResponse::Rejected { .. } => Err(SessionChildError::ProtocolFailed),
        SessionChildResponse::Ready { .. } => Err(SessionChildError::ProtocolFailed),
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
    writer: Option<JoinHandle<Result<(), SessionChildError>>>,
    writer_rx: Receiver<Result<(), SessionChildError>>,
    reader: Option<JoinHandle<()>>,
    response_rx: Receiver<Result<Vec<u8>, SessionChildError>>,
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
            .map_err(|_| SessionChildError::SpawnFailed)?;
        let mut child = child;
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                kill_and_reap(&mut child);
                return Err(SessionChildError::IoFailed);
            }
        };
        let mut stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                kill_and_reap(&mut child);
                return Err(SessionChildError::IoFailed);
            }
        };
        let (writer_tx, writer_rx) = mpsc::channel();
        let writer = thread::spawn(move || {
            let mut stdin = stdin;
            let result = stdin
                .write_all(&payload)
                .and_then(|_| stdin.write_all(b"\n"))
                .and_then(|_| stdin.flush())
                .map_err(|_| SessionChildError::IoFailed);
            drop(stdin);
            let _ = writer_tx.send(result.clone());
            result
        });
        let (response_tx, response_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let _ = response_tx.send(read_child_response(&mut stdout));
        });
        Ok(Self {
            child: Some(child),
            writer: Some(writer),
            writer_rx,
            reader: Some(reader),
            response_rx,
        })
    }

    fn wait_writer(&self, deadline: Instant) -> Result<(), SessionChildError> {
        wait_result(&self.writer_rx, deadline)
    }

    fn wait_reader(&self, deadline: Instant) -> Result<Vec<u8>, SessionChildError> {
        wait_result(&self.response_rx, deadline)
    }

    fn kill_and_reap(&mut self) {
        if let Some(child) = self.child.as_mut() {
            kill_and_reap(child);
        }
    }

    fn finish(&mut self) {
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
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
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SessionChildError::TimedOut),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SessionChildError::IoFailed),
    }
}

fn read_child_response(reader: &mut impl Read) -> Result<Vec<u8>, SessionChildError> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .map_err(|_| SessionChildError::IoFailed)?;
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
    reader: impl Read,
    mut writer: impl Write,
    dropper: &impl PrivilegeDropper,
    fd_sanitizer: &impl InheritedFdSanitizer,
    auditor: &impl PostDropAuditor,
    child_pid: u32,
) -> i32 {
    let mut bytes = Vec::new();
    if reader
        .take((protocol::MAX_SESSION_CHILD_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return 1;
    }
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
    let allowed_terminal_fds = terminal
        .as_ref()
        .map_or_else(Vec::new, |value| vec![value.fd]);
    if fd_sanitizer
        .sanitize_with_allowlist(&allowed_terminal_fds)
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
        Err(_) => {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::PrivilegeDropFailed);
            return 1;
        }
    };
    let applied_credentials = SessionChildUnixCredentials::from(&applied);
    if applied_credentials != SessionChildUnixCredentials::from(&target) {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::CredentialMismatch);
        return 1;
    }
    let proof = match auditor.audit() {
        Ok(proof) => proof,
        Err(_) => {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::IsolationAuditFailed);
            return 1;
        }
    };
    if let Err(error) = validate_isolation_proof_with_allowed_fds(&proof, &allowed_terminal_fds) {
        eprintln!(
            "session child isolation policy failed error={error} effective_capability_count={} permitted_capability_count={} inheritable_capability_count={} ambient_capability_count={} bounding_capability_count={} securebits={} no_new_privs={} open_fd_count={}",
            proof.capabilities.effective.len(),
            proof.capabilities.permitted.len(),
            proof.capabilities.inheritable.len(),
            proof.capabilities.ambient.len(),
            proof.capabilities.bounding.len(),
            proof.securebits,
            proof.no_new_privs,
            proof.open_fds.len(),
        );
        let _ = write_rejection(&mut writer, SessionChildErrorCode::IsolationPolicyFailed);
        return 1;
    }
    // The production child replaces itself with the trusted probe. Test seams use
    // synthetic PIDs and retain the response path for deterministic unit tests.
    let terminal_proof = if child_pid == std::process::id() {
        if unsafe { libc::setsid() } < 0 {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::SessionBoundaryFailed);
            return 1;
        }
        let terminal = match terminal.as_ref() {
            Some(terminal) if terminal.fd == 3 => terminal,
            _ => {
                let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
                return 1;
            }
        };
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(terminal.fd, &mut stat) } < 0
            || libc::major(stat.st_rdev) as u32 != terminal.device_major
            || libc::minor(stat.st_rdev) as u32 != terminal.device_minor
        {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        if unsafe { libc::ioctl(terminal.fd, libc::TIOCSCTTY, 0) } < 0 {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        let previous_sigttou = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
        let foreground = unsafe { libc::tcsetpgrp(terminal.fd, libc::getpgrp()) };
        unsafe { libc::signal(libc::SIGTTOU, previous_sigttou) };
        if foreground != 0 {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        let sid = unsafe { libc::tcgetsid(terminal.fd) };
        let pgid = unsafe { libc::tcgetpgrp(terminal.fd) };
        let pid = unsafe { libc::getpid() };
        if sid <= 0 || pgid <= 0 || sid as u32 != pid as u32 || pgid as u32 != pid as u32 {
            let _ = write_rejection(&mut writer, SessionChildErrorCode::TerminalProofFailed);
            return 1;
        }
        unsafe { libc::close(terminal.fd) };
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
        let probe = match runtime.probe_path.to_path_buf() {
            Ok(path) if path.is_absolute() => path,
            _ => {
                let _ = write_rejection(&mut writer, SessionChildErrorCode::InvalidRuntimeContext);
                return 1;
            }
        };
        let mut command = std::process::Command::new(probe);
        command
            .arg(&canonical_username)
            .arg(&session_id)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .env_clear()
            .env("HOME", home)
            .env("USER", &canonical_username)
            .env("LOGNAME", &canonical_username)
            .env(
                "SHELL",
                runtime.shell.to_path_buf().ok().unwrap_or_default(),
            )
            .env("PATH", DEFAULT_SESSION_PATH)
            .env("XDG_SESSION_TYPE", &runtime.session_type);
        if let Some(terminal) = terminal.as_ref() {
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
        let error = std::os::unix::process::CommandExt::exec(&mut command);
        let _ = write_rejection(&mut writer, SessionChildErrorCode::ExecFailed);
        let _ = error;
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
                cwd: runtime.home,
            },
            exec_probe_version: SESSION_EXEC_PROBE_VERSION,
            terminal_proof,
        },
    };
    if serde_json::to_writer(&mut writer, &response).is_err()
        || writer.write_all(b"\n").is_err()
        || writer.flush().is_err()
    {
        return 1;
    }
    0
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
