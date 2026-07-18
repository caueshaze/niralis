use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{
    SessionError, SessionExecPlan, SessionRequest, SupervisorFixtureBoundaryMode,
    SupervisorFixtureSnapshot, WorkerSecret, WorkerSessionLauncher,
};
use tempfile::TempDir;

const RECOVERY_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct Fixture {
    pub(super) launcher: WorkerSessionLauncher,
    pub(super) listener: UnixListener,
    _directory: TempDir,
}

pub(super) struct ReportedProcesses {
    pub(super) worker: u32,
    pub(super) leader: u32,
    pub(super) member: u32,
    pub(super) report: BufReader<UnixStream>,
}

pub(super) struct ProcessCleanup(Vec<u32>);

impl ProcessCleanup {
    pub(super) fn new(processes: &ReportedProcesses) -> Self {
        Self(vec![processes.worker, processes.leader, processes.member])
    }
}

impl Drop for ProcessCleanup {
    fn drop(&mut self) {
        for pid in self.0.iter().copied() {
            let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
    }
}

impl Fixture {
    pub(super) fn new(mode: SupervisorFixtureBoundaryMode, post_ack_barrier: bool) -> Self {
        let directory = tempfile::tempdir().expect("fixture directory");
        let socket = directory.path().join("process-report.sock");
        let listener = UnixListener::bind(&socket).expect("fixture report listener");
        let mut environment = vec![(
            "NIRALIS_SUPERVISOR_FIXTURE_SOCKET".to_owned(),
            socket
                .into_os_string()
                .into_string()
                .expect("UTF-8 socket path"),
        )];
        if post_ack_barrier {
            environment.push((
                "NIRALIS_SUPERVISOR_FIXTURE_POST_ACK_BARRIER".to_owned(),
                "1".to_owned(),
            ));
        }
        let mut launcher = WorkerSessionLauncher::new(
            PathBuf::from(env!("CARGO_BIN_EXE_fixture-supervisor-worker")),
            PathBuf::from("/fixture/session-child"),
            PathBuf::from("/fixture/session-probe"),
            RECOVERY_TIMEOUT,
            environment,
        )
        .expect("fixture launcher");
        launcher.use_supervisor_test_fixture_mode_for_test(mode, false);
        Self {
            launcher,
            listener,
            _directory: directory,
        }
    }

    pub(super) fn launch(&self) -> Result<(), SessionError> {
        self.launcher
            .start_pam_session_for_test(
                session_request(),
                launch_plan(),
                "niralis-supervisor-fixture".to_owned(),
                WorkerSecret::new("fixture-secret".to_owned()),
            )
            .map(|_| ())
    }

    pub(super) fn receive_processes(&self) -> ReportedProcesses {
        let (stream, _) = self.listener.accept().expect("worker report connection");
        let mut report = BufReader::new(stream);
        let mut line = String::new();
        report.read_line(&mut line).expect("worker process report");
        let mut fields = line
            .split_ascii_whitespace()
            .map(|field| field.parse::<u32>().expect("reported process identifier"));
        let processes = ReportedProcesses {
            worker: fields.next().expect("worker PID"),
            leader: fields.next().expect("leader PID"),
            member: fields.next().expect("member PID"),
            report,
        };
        assert!(fields.next().is_none(), "unexpected process report field");
        processes
    }

    pub(super) fn register_payload(&self, processes: &ReportedProcesses) {
        self.launcher
            .register_supervisor_fixture_payload_members_for_test(&[
                processes.leader,
                processes.member,
            ])
            .expect("register fixture boundary members");
    }

    pub(super) fn wait_recovery(&self) -> SupervisorFixtureSnapshot {
        self.launcher
            .wait_for_supervisor_fixture_recovery_for_test(RECOVERY_TIMEOUT)
            .expect("supervisor recovery completion")
    }
}
pub(super) fn assert_recovered(snapshot: SupervisorFixtureSnapshot, expected_kills: usize) {
    assert_eq!(snapshot.emergency_kills, expected_kills);
    assert_eq!(snapshot.proofs, snapshot.prepares);
    assert_eq!(snapshot.unrefs, snapshot.prepares);
    assert_eq!(snapshot.logind_terminations, snapshot.prepares);
    assert_eq!(snapshot.vt_recoveries, snapshot.prepares);
}

pub(super) fn session_request() -> SessionRequest {
    SessionRequest {
        username: "fixture-user".to_owned(),
        session: SessionInfo {
            id: "niri".to_owned(),
            name: "Niri".to_owned(),
            kind: SessionKind::Wayland,
        },
    }
}

pub(super) fn launch_plan() -> SessionExecPlan {
    SessionExecPlan {
        source_path: b"/fixture/niri.desktop".to_vec(),
        executable: b"/bin/true".to_vec(),
        argv: vec![b"true".to_vec()],
    }
}

pub(super) fn kill_process(pid: u32) {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    assert_eq!(result, 0, "SIGKILL process {pid}");
}

pub(super) fn kill_and_observe(pid: u32) {
    let pidfd = pidfd_open(pid);
    kill_process(pid);
    wait_pidfd_terminal(&pidfd);
}

pub(super) fn pidfd_open(pid: u32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    assert!(fd >= 0, "pidfd_open({pid}) failed");
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

pub(super) fn wait_pidfd_terminal(pidfd: &OwnedFd) {
    let mut descriptor = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut descriptor, 1, 5_000) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        assert_eq!(result, 1, "pidfd did not become terminal");
        assert_ne!(descriptor.revents & libc::POLLIN, 0);
        return;
    }
}
