mod protocol;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use protocol::{
    SessionChildEnvelope, SessionChildErrorCode, SessionChildRequest, SessionChildResponse,
    SESSION_CHILD_PROTOCOL_VERSION,
};

pub const SESSION_CHILD_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChildExpectation {
    pub canonical_username: String,
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionChildReport {
    pub canonical_username: String,
    pub session_id: String,
    pub child_pid: u32,
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
        let child = Command::new(&self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env_clear()
            .current_dir("/")
            .spawn()
            .map_err(|_| SessionChildError::SpawnFailed)?;
        let mut attempt = ChildAttempt { child };
        let pid = attempt.child.id();
        let stdin = attempt
            .child
            .stdin
            .take()
            .ok_or(SessionChildError::IoFailed)?;
        let mut stdout = attempt
            .child
            .stdout
            .take()
            .ok_or(SessionChildError::IoFailed)?;
        let request = SessionChildEnvelope {
            version: SESSION_CHILD_PROTOCOL_VERSION,
            message: SessionChildRequest::Probe {
                canonical_username: expectation.canonical_username.clone(),
                session_id: expectation.session_id.clone(),
            },
        };
        let payload = serde_json::to_vec(&request).map_err(|_| SessionChildError::IoFailed)?;
        if payload.len() + 1 > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES {
            return Err(SessionChildError::ProtocolFailed);
        }
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = read_child_response(&mut stdout);
            let _ = sender.send(result);
        });
        let mut stdin = stdin;
        stdin
            .write_all(&payload)
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|_| SessionChildError::IoFailed)?;
        drop(stdin);
        let bytes = match receiver.recv_timeout(SESSION_CHILD_HANDSHAKE_TIMEOUT) {
            Ok(result) => result?,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(SessionChildError::TimedOut);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(SessionChildError::IoFailed);
            }
        };
        let status = attempt
            .child
            .wait()
            .map_err(|_| SessionChildError::IoFailed)?;
        if !status.success() {
            return Err(SessionChildError::ExitFailed);
        }
        let response: SessionChildEnvelope<SessionChildResponse> = parse_response(&bytes)?;
        if response.version != SESSION_CHILD_PROTOCOL_VERSION {
            return Err(SessionChildError::ProtocolFailed);
        }
        match response.message {
            SessionChildResponse::Ready {
                canonical_username,
                session_id,
                child_pid,
            } if canonical_username == expectation.canonical_username
                && session_id == expectation.session_id
                && child_pid == pid =>
            {
                Ok(SessionChildReport {
                    canonical_username,
                    session_id,
                    child_pid,
                })
            }
            SessionChildResponse::Rejected { .. } => Err(SessionChildError::ProtocolFailed),
            SessionChildResponse::Ready { .. } => Err(SessionChildError::ProtocolFailed),
        }
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

struct ChildAttempt {
    child: Child,
}

impl Drop for ChildAttempt {
    fn drop(&mut self) {
        kill_and_reap(&mut self.child);
    }
}

pub(crate) fn run_child_process() -> i32 {
    let stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut bytes = Vec::new();
    if stdin
        .take((protocol::MAX_SESSION_CHILD_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return 1;
    }
    let request: SessionChildEnvelope<SessionChildRequest> = match parse_request(&bytes) {
        Ok(request) => request,
        Err(code) => {
            let _ = write_rejection(&mut stdout, code);
            return 1;
        }
    };
    if request.version != SESSION_CHILD_PROTOCOL_VERSION {
        let _ = write_rejection(&mut stdout, SessionChildErrorCode::UnsupportedVersion);
        return 1;
    }
    let SessionChildRequest::Probe {
        canonical_username,
        session_id,
    } = request.message;
    let response = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildResponse::Ready {
            canonical_username,
            session_id,
            child_pid: std::process::id(),
        },
    };
    if serde_json::to_writer(&mut stdout, &response).is_err()
        || stdout.write_all(b"\n").is_err()
        || stdout.flush().is_err()
    {
        return 1;
    }
    0
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
