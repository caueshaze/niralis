mod protocol;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::isolation::{
    validate_isolation_proof, InheritedFdSanitizer, LinuxInheritedFdSanitizer,
    LinuxPostDropAuditor, PostDropAuditor, PostDropIsolationProof,
};
use crate::privilege_drop::{
    AppliedCredentials, LibcPrivilegeDropper, PrivilegeDropError, PrivilegeDropTarget,
    PrivilegeDropper,
};
use protocol::{
    SessionChildEnvelope, SessionChildErrorCode, SessionChildIsolationProof, SessionChildRequest,
    SessionChildResponse, SessionChildUnixCredentials, SESSION_CHILD_PROTOCOL_VERSION,
};

pub const SESSION_CHILD_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChildExpectation {
    pub canonical_username: String,
    pub session_id: String,
    pub target_credentials: PrivilegeDropTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChildReport {
    pub canonical_username: String,
    pub session_id: String,
    pub child_pid: u32,
    pub applied_credentials: AppliedCredentials,
    pub isolation_proof: PostDropIsolationProof,
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
}

pub trait SessionChildRunnerFactory: Send + Sync {
    fn build(&self, path: &Path) -> Result<Box<dyn SessionChildRunner>, SessionChildError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessSessionChildRunnerFactory;

impl SessionChildRunnerFactory for ProcessSessionChildRunnerFactory {
    fn build(&self, path: &Path) -> Result<Box<dyn SessionChildRunner>, SessionChildError> {
        Ok(Box::new(ProcessSessionChildRunner::new(
            path.to_path_buf(),
        )?))
    }
}

#[derive(Debug, Clone)]
pub struct ProcessSessionChildRunner {
    path: PathBuf,
}

impl ProcessSessionChildRunner {
    pub fn new(path: PathBuf) -> Result<Self, SessionChildError> {
        if !path.is_absolute() {
            return Err(SessionChildError::InvalidPath);
        }
        Ok(Self { path })
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
            },
        };
        let payload = serde_json::to_vec(&request).map_err(|_| SessionChildError::IoFailed)?;
        if payload.len() + 1 > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
            return Err(SessionChildError::ProtocolFailed);
        }
        let mut attempt = SessionChildAttempt::spawn(&self.path, payload)?;
        let pid = attempt.child.id();
        let writer_result = attempt.wait_writer(deadline);
        let reader_result = match &writer_result {
            Ok(()) => attempt.wait_reader(deadline),
            Err(error) => Err(error.clone()),
        };
        let status_result = if writer_result.is_ok() && reader_result.is_ok() {
            attempt.wait_child(deadline)
        } else {
            Ok(None)
        };
        let needs_cleanup = writer_result.is_err()
            || reader_result.is_err()
            || status_result.is_err()
            || matches!(status_result, Ok(None));
        if needs_cleanup {
            attempt.kill_and_reap();
        }
        attempt.finish();
        writer_result?;
        let bytes = reader_result?;
        let status = status_result?.ok_or(SessionChildError::TimedOut)?;
        if !status.success() {
            return Err(SessionChildError::ExitFailed);
        }
        let response: SessionChildEnvelope<SessionChildResponse> = parse_response(&bytes)?;
        if response.version != SESSION_CHILD_PROTOCOL_VERSION {
            return Err(SessionChildError::ProtocolFailed);
        }
        validate_ready_response(response.message, &expectation, pid)
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
            isolation_proof,
        } if canonical_username == expectation.canonical_username
            && session_id == expectation.session_id
            && child_pid == pid
            && applied_credentials
                == SessionChildUnixCredentials::from(&expectation.target_credentials)
            && validate_isolation_proof(&PostDropIsolationProof::from(isolation_proof.clone()))
                .is_ok() =>
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
            })
        }
        SessionChildResponse::Rejected { .. } => Err(SessionChildError::ProtocolFailed),
        SessionChildResponse::Ready { .. } => Err(SessionChildError::ProtocolFailed),
    }
}

const CHILD_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

struct SessionChildAttempt {
    child: Child,
    writer: Option<JoinHandle<Result<(), SessionChildError>>>,
    writer_rx: Receiver<Result<(), SessionChildError>>,
    reader: Option<JoinHandle<()>>,
    response_rx: Receiver<Result<Vec<u8>, SessionChildError>>,
}

impl SessionChildAttempt {
    fn spawn(path: &Path, payload: Vec<u8>) -> Result<Self, SessionChildError> {
        let child = Command::new(path)
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
            child,
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

    fn wait_child(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<std::process::ExitStatus>, SessionChildError> {
        loop {
            remaining(deadline)?;
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|_| SessionChildError::IoFailed)?
            {
                remaining(deadline)?;
                return Ok(Some(status));
            }
            let remaining = remaining(deadline)?;
            thread::sleep(CHILD_WAIT_POLL_INTERVAL.min(remaining));
        }
    }

    fn kill_and_reap(&mut self) {
        kill_and_reap(&mut self.child);
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
    reader
        .take((protocol::MAX_SESSION_CHILD_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SessionChildError::IoFailed)?;
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
    } = request.message;
    if credentials.uid == 0 {
        let _ = write_rejection(&mut writer, SessionChildErrorCode::RootUidDisallowed);
        return 1;
    }
    if fd_sanitizer.sanitize().is_err() {
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
    if let Err(error) = validate_isolation_proof(&proof) {
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
    let response = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildResponse::Ready {
            canonical_username,
            session_id,
            child_pid,
            applied_credentials,
            isolation_proof: SessionChildIsolationProof::from(&proof),
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
