use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{
    PayloadScopeIdentity, PayloadScopeRecoveryReason, SessionExecPlan, SessionRequest,
    WorkerControlRequest, WorkerEnvelope, WorkerRequest, WorkerResponse, WorkerSecret,
    WorkerSessionLauncher,
};

const HARNESS_TIMEOUT: Duration = Duration::from_secs(3);

fn duplicate_inherited_fd(fd: libc::c_int) -> OwnedFd {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    assert!(duplicate >= 10, "duplicate inherited fixture descriptor");
    unsafe { OwnedFd::from_raw_fd(duplicate) }
}

struct FullWorker {
    child: Child,
    supervisor: Option<UnixStream>,
    stdout: BufReader<ChildStdout>,
    harness: BufReader<UnixStream>,
    events: Vec<String>,
    leader_pid: Option<u32>,
    member_pid: Option<u32>,
    _control_dir: Option<tempfile::TempDir>,
    control_path: std::path::PathBuf,
}
