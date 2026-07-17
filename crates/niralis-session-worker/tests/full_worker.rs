#![cfg(feature = "worker-test-fixtures")]

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
    _control_dir: Option<tempfile::TempDir>,
    control_path: std::path::PathBuf,
}

impl FullWorker {
    fn spawn(mode: &str) -> Self {
        let mut worker = Self::spawn_process(mode, false);
        worker.expect("ScopePrepared");
        worker.expect("PinAcquired");
        worker.expect("CommitExecCalled:count=1");
        worker.expect("Running");
        worker.expect("TimerFdCloexec");
        worker.assert_started_frame();
        worker
    }

    fn spawn_barrier(mode: &str) -> Self {
        Self::spawn_process(mode, true)
    }

    fn spawn_process(mode: &str, with_control: bool) -> Self {
        let (parent_harness, child_harness) = UnixStream::pair().expect("harness socketpair");
        let (parent_supervisor, child_supervisor) =
            UnixStream::pair().expect("supervisor socketpair");
        parent_harness
            .set_read_timeout(Some(HARNESS_TIMEOUT))
            .expect("bounded harness timeout");
        parent_harness
            .set_write_timeout(Some(HARNESS_TIMEOUT))
            .expect("bounded harness write timeout");
        let inherited_harness = duplicate_inherited_fd(child_harness.as_raw_fd());
        let inherited_supervisor = duplicate_inherited_fd(child_supervisor.as_raw_fd());
        drop(child_harness);
        drop(child_supervisor);
        let harness_fd = inherited_harness.as_raw_fd();
        let supervisor_fd = inherited_supervisor.as_raw_fd();
        let mut command = Command::new(env!("CARGO_BIN_EXE_fixture-full-worker"));
        command
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("NIRALIS_FULL_WORKER_HARNESS_FD", "3")
            .env(niralis_session::WORKER_SUPERVISOR_FD_ENV, "4");
        unsafe {
            command.pre_exec(move || {
                if harness_fd != 3 && libc::dup2(harness_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let flags = libc::fcntl(3, libc::F_GETFD);
                if flags < 0 || libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(supervisor_fd, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let flags = libc::fcntl(4, libc::F_GETFD);
                if flags < 0 || libc::fcntl(4, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let control_dir = with_control.then(|| tempfile::tempdir().expect("control tempdir"));
        let control_path = control_dir
            .as_ref()
            .map_or_else(std::path::PathBuf::new, |dir| {
                dir.path().join("worker.sock")
            });
        let mut child = command.spawn().expect("spawn full worker fixture");
        drop(inherited_harness);
        drop(inherited_supervisor);
        let stdin = child.stdin.take().expect("worker protocol stdin");
        let stdout = BufReader::new(child.stdout.take().expect("worker protocol stdout"));
        let mut worker = Self {
            child,
            supervisor: Some(parent_supervisor),
            stdout,
            harness: BufReader::new(parent_harness),
            events: Vec::new(),
            leader_pid: None,
            _control_dir: control_dir,
            control_path,
        };
        worker.expect("BootstrapEntered");
        worker.expect("SignalMaskInstalled");
        worker.expect("SignalFdCloexec");
        worker.expect("SupervisorFdCloexec");
        worker.send_request(stdin);
        worker.expect("RequestAccepted");
        worker.expect("VtAcquired");
        worker.expect("PamOpened");
        worker.expect("PayloadSignalMaskRestored");
        worker.expect("PayloadFdHygieneVerified");
        worker.expect_prefix("LeaderPid:");
        worker.expect("PendingExecHandoffReady");
        worker
    }

    fn send_request(&mut self, mut stdin: ChildStdin) {
        let request = WorkerEnvelope {
            version: niralis_session::WORKER_PROTOCOL_VERSION,
            message: WorkerRequest::PamSession {
                request: SessionRequest {
                    username: "fixture-user".into(),
                    session: SessionInfo {
                        id: "niri".into(),
                        name: "Niri".into(),
                        kind: SessionKind::Wayland,
                    },
                },
                launch_plan: SessionExecPlan {
                    source_path: b"/fixture.desktop".to_vec(),
                    executable: b"/bin/true".to_vec(),
                    argv: vec![b"true".to_vec()],
                },
                pam_service: "niralis-fixture".into(),
                password: WorkerSecret::new("fixture-secret".into()),
                session_child_path: "/fixture/session-child".into(),
                session_probe_path: "/fixture/session-probe".into(),
                control_path: self.control_path.clone(),
                worker_id: "fixture-worker".into(),
                launcher_pid: std::process::id(),
            },
        };
        serde_json::to_writer(&mut stdin, &request).expect("serialize worker request");
        stdin.write_all(b"\n").expect("frame worker request");
        stdin.flush().expect("flush worker request");
        drop(stdin);
    }

    fn assert_started_frame(&mut self) {
        let envelope = self.read_response();
        assert_eq!(envelope.version, niralis_session::WORKER_PROTOCOL_VERSION);
        assert!(matches!(envelope.message, WorkerResponse::Started { .. }));
    }

    fn read_response(&mut self) -> WorkerEnvelope<WorkerResponse> {
        if self.stdout.buffer().is_empty() {
            let mut pollfd = libc::pollfd {
                fd: self.stdout.get_ref().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe {
                    libc::poll(
                        &mut pollfd,
                        1,
                        i32::try_from(HARNESS_TIMEOUT.as_millis()).unwrap(),
                    )
                },
                1,
                "production protocol response timed out; events={:?}",
                self.events
            );
        }
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .expect("read production worker response");
        assert!(line.len() <= niralis_session::MAX_WORKER_MESSAGE_BYTES);
        serde_json::from_str(&line).expect("parse production worker response")
    }

    fn expect_preparing(&mut self) {
        let envelope = self.read_response();
        assert_eq!(envelope.version, niralis_session::WORKER_PROTOCOL_VERSION);
        assert!(matches!(
            envelope.message,
            WorkerResponse::Preparing { ref worker_id } if worker_id == "fixture-worker"
        ));
    }

    fn expect_prepared(&mut self) -> (String, PayloadScopeIdentity) {
        let envelope = self.read_response();
        match envelope.message {
            WorkerResponse::PayloadScopePrepared {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                scope_identity,
                ..
            } => {
                assert_eq!(worker_id, "fixture-worker");
                assert_eq!(expected_worker_pid, self.child.id());
                assert_eq!(registration_nonce, scope_identity.invocation_id);
                (registration_nonce, scope_identity)
            }
            response => panic!("expected PayloadScopePrepared, got {response:?}"),
        }
    }

    fn acknowledge_scope(&mut self, registration_nonce: &str) {
        let stream = self
            .supervisor
            .as_mut()
            .expect("dedicated supervisor channel remains connected");
        niralis_session::write_control_request(
            stream,
            WorkerControlRequest::PayloadScopeRegistered {
                worker_id: "fixture-worker".into(),
                expected_worker_pid: self.child.id(),
                registration_nonce: registration_nonce.to_owned(),
            },
        )
        .expect("send authenticated scope acknowledgement");
    }

    fn expect_release_ready(&mut self) {
        let envelope = self.read_response();
        assert!(matches!(
            envelope.message,
            WorkerResponse::PayloadScopeReleaseReady { ref worker_id }
                if worker_id == "fixture-worker"
        ));
    }

    fn answer_release(&mut self, recovery: bool) {
        self.expect_release_ready();
        let mut stream = self
            .supervisor
            .take()
            .expect("dedicated supervisor channel remains connected");
        let request = niralis_session::read_control_request(&mut stream)
            .expect("read authenticated release request");
        let (
            worker_id,
            expected_worker_pid,
            registration_nonce,
            release_nonce,
            scope_identity,
            local_cleanup_succeeded,
        ) = match request.message {
            WorkerControlRequest::PayloadScopeReleaseRequested {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                release_nonce,
                scope_identity,
                local_cleanup_succeeded,
            } => (
                worker_id,
                expected_worker_pid,
                registration_nonce,
                release_nonce,
                scope_identity,
                local_cleanup_succeeded,
            ),
            request => panic!("expected release request, got {request:?}"),
        };
        assert_eq!(worker_id, "fixture-worker");
        assert_eq!(expected_worker_pid, self.child.id());
        assert!(scope_identity.validate());
        assert!(local_cleanup_succeeded);
        self.expect("PayloadScopeReleaseRequested:count=1");
        let response = if recovery {
            WorkerControlRequest::PayloadScopeRecoveryRequired {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                release_nonce,
                reason: PayloadScopeRecoveryReason::IdentityMismatch,
            }
        } else {
            WorkerControlRequest::PayloadScopeReleased {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                release_nonce,
            }
        };
        niralis_session::write_control_request(&mut stream, response)
            .expect("send authenticated release result");
        self.supervisor = Some(stream);
    }

    fn read_event(&mut self) -> String {
        let mut bytes = Vec::new();
        let count = self
            .harness
            .read_until(b'\n', &mut bytes)
            .expect("bounded harness event read");
        assert_ne!(
            count, 0,
            "fixture closed harness channel; events={:?}",
            self.events
        );
        assert!(bytes.len() <= 256, "oversized harness frame");
        assert_eq!(bytes.pop(), Some(b'\n'), "unterminated harness frame");
        let event = String::from_utf8(bytes).expect("UTF-8 harness event");
        if let Some(value) = event.strip_prefix("LeaderPid:") {
            self.leader_pid = Some(value.parse().expect("numeric leader pid"));
        }
        self.events.push(event.clone());
        event
    }

    fn expect(&mut self, expected: &str) {
        let event = self.read_event();
        assert_eq!(event, expected, "unexpected harness event sequence");
    }

    fn expect_prefix(&mut self, prefix: &str) -> String {
        let event = self.read_event();
        assert!(
            event.starts_with(prefix),
            "expected prefix {prefix:?}, got {event:?}"
        );
        event
    }

    fn signal(&self, signal: libc::c_int) {
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, signal) },
            0
        );
    }

    fn send_harness_command(&mut self, command: &str) {
        assert!(command.len() <= 63 && !command.as_bytes().contains(&b'\n'));
        let stream = self.harness.get_mut();
        stream
            .write_all(command.as_bytes())
            .expect("write bounded harness command");
        stream.write_all(b"\n").expect("frame harness command");
        stream.flush().expect("flush harness command");
    }

    fn continue_phase(&mut self, phase: &str) {
        self.send_harness_command(&format!("ContinuePhase:{phase}"));
    }

    fn disconnect_supervisor(&mut self) {
        drop(self.supervisor.take());
    }

    fn assert_process_alive(&self, pid: u32) {
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, 0);
    }

    fn expect_session_failed(&mut self) {
        let envelope = self.read_response();
        assert!(matches!(
            envelope.message,
            WorkerResponse::SessionFailed { .. }
        ));
    }

    fn finish_cancelled_launch(&mut self) {
        self.expect("PamCloseStarted");
        self.expect("PamCloseCompleted");
        self.expect("PamDropped");
        self.expect("VtReleased");
        self.expect("WorkerReturning");
        self.expect_session_failed();
        let status = self.child.wait().expect("reap cancelled worker fixture");
        assert_eq!(status.code(), Some(1));
    }

    fn assert_event_absent(&self, prefix: &str) {
        assert!(
            !self.events.iter().any(|event| event.starts_with(prefix)),
            "unexpected event with prefix {prefix:?}: {:?}",
            self.events
        );
    }

    fn finish_cooperative(&mut self, cause: &str) {
        self.expect(cause);
        self.expect("GracefulRequestObserved:count=1");
        self.send_harness_command("AllowPayloadExit");
        self.expect("TimerArmed");
        self.expect("LeaderReaped");
        self.send_harness_command("MakeBoundaryTerminal");
        self.expect("BoundaryCandidate");
        self.expect("BoundaryEmptyProofEstablished:count=1");
        self.expect("BoundaryEmptyProofAccepted");
        self.expect("UnitUnrefAttempted:count=1");
        self.expect("PamCloseStarted");
        self.expect("PamCloseCompleted");
        self.expect("PamDropped");
        self.expect("VtReleased");
        self.expect("WorkerReturning");
        let status = self.child.wait().expect("reap full worker fixture");
        assert!(
            status.success(),
            "full worker returned {status:?}; events={:?}",
            self.events
        );
    }

    fn teardown_non_cooperative(&mut self) {
        let leader = self.leader_pid.expect("real leader pid recorded");
        self.assert_process_alive(self.child.id());
        self.assert_process_alive(leader);
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGKILL) },
            0
        );
        let status = self
            .child
            .wait()
            .expect("reap test fixture after assertions");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    fn teardown_retained_worker(&mut self) {
        self.assert_process_alive(self.child.id());
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGKILL) },
            0
        );
        let status = self.child.wait().expect("reap retained worker fixture");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    fn assert_running_ownership_retained(&self) {
        self.assert_event_absent("TimerArmed");
        self.assert_event_absent("BoundaryEmptyProofAccepted");
        self.assert_event_absent("UnitUnrefAttempted");
        self.assert_event_absent("PamClose");
        self.assert_event_absent("VtReleased");
        self.assert_event_absent("WorkerReturning");
    }
}

impl Drop for FullWorker {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

trait ExitStatusSignal {
    fn signal(&self) -> Option<i32>;
}

impl ExitStatusSignal for std::process::ExitStatus {
    fn signal(&self) -> Option<i32> {
        std::os::unix::process::ExitStatusExt::signal(self)
    }
}

fn cooperative_signal(signal: libc::c_int, cause: &str) {
    let mut worker = FullWorker::spawn("cooperative");
    worker.signal(signal);
    worker.finish_cooperative(cause);
}

#[test]
fn full_worker_sigterm_cooperative() {
    cooperative_signal(libc::SIGTERM, "Cause:Sigterm");
}

#[test]
fn full_worker_sigint_cooperative() {
    cooperative_signal(libc::SIGINT, "Cause:Sigint");
}

#[test]
fn full_worker_sighup_cooperative() {
    cooperative_signal(libc::SIGHUP, "Cause:Sighup");
}

#[test]
fn full_worker_sigterm_non_cooperative_deadline() {
    let mut worker = FullWorker::spawn("non-cooperative");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("TimerArmed");
    worker.expect("DeadlineExpired");
    worker.expect("NeedsEscalation");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    assert!(!worker.events.iter().any(|event| {
        event.starts_with("BoundaryEmptyProof")
            || event.starts_with("UnitUnrefAttempted")
            || event.starts_with("PamClose")
            || event == "VtReleased"
            || event == "WorkerReturning"
    }));
    worker.teardown_non_cooperative();
}

#[test]
fn full_worker_invalidation_before_kill_preserves_pam_vt() {
    let mut worker = FullWorker::spawn("invalidation-before-kill");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("InvocationInvalidatedBeforeKill");
    worker.expect("NeedsEscalation");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    worker.assert_running_ownership_retained();
    worker.teardown_non_cooperative();
}

#[test]
fn full_worker_bus_loss_before_kill_preserves_pam_vt() {
    let mut worker = FullWorker::spawn("bus-loss-before-kill");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("SystemBusLostBeforeKill");
    worker.expect("NeedsEscalation");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    worker.assert_running_ownership_retained();
    worker.teardown_non_cooperative();
}

#[test]
fn full_worker_replacement_during_proof_enters_recovery() {
    let mut worker = FullWorker::spawn("replacement-during-proof");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.send_harness_command("AllowPayloadExit");
    worker.expect("TimerArmed");
    worker.expect("LeaderReaped");
    worker.send_harness_command("MakeBoundaryTerminal");
    worker.expect("BoundaryCandidate");
    worker.expect("InvocationReplacedDuringProof");
    worker.expect("RecoveryRequired");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    worker.assert_event_absent("BoundaryEmptyProofAccepted");
    worker.assert_event_absent("UnitUnrefAttempted");
    worker.assert_event_absent("PamClose");
    worker.assert_event_absent("VtReleased");
    worker.assert_event_absent("WorkerReturning");
    worker.teardown_retained_worker();
}

#[test]
fn full_worker_supervisor_disconnect() {
    let mut worker = FullWorker::spawn("cooperative");
    worker.disconnect_supervisor();
    worker.finish_cooperative("Cause:SupervisorDisconnected");
}

#[test]
fn full_worker_signal_then_supervisor_disconnect() {
    let mut worker = FullWorker::spawn("cooperative");
    worker.signal(libc::SIGTERM);
    worker.disconnect_supervisor();
    worker.finish_cooperative("Cause:Sigterm");
}

#[test]
fn full_worker_signal_mask_installed_before_runtime() {
    let mut worker = FullWorker::spawn("cooperative");
    let installed = worker
        .events
        .iter()
        .position(|event| event == "SignalMaskInstalled")
        .unwrap();
    let accepted = worker
        .events
        .iter()
        .position(|event| event == "RequestAccepted")
        .unwrap();
    assert!(installed < accepted);
    worker.signal(libc::SIGTERM);
    worker.finish_cooperative("Cause:Sigterm");
}

#[test]
fn full_worker_payload_signal_mask_restored() {
    let mut worker = FullWorker::spawn("cooperative");
    assert!(worker
        .events
        .iter()
        .any(|event| event == "PayloadSignalMaskRestored"));
    worker.signal(libc::SIGTERM);
    worker.finish_cooperative("Cause:Sigterm");
}

#[test]
fn full_worker_fd_cloexec_hygiene() {
    let mut worker = FullWorker::spawn("cooperative");
    assert!(worker
        .events
        .iter()
        .any(|event| event == "PayloadFdHygieneVerified"));
    assert!(worker.events.iter().any(|event| event == "SignalFdCloexec"));
    assert!(worker
        .events
        .iter()
        .any(|event| event == "SupervisorFdCloexec"));
    assert!(worker.events.iter().any(|event| event == "TimerFdCloexec"));
    worker.signal(libc::SIGTERM);
    worker.finish_cooperative("Cause:Sigterm");
}

#[test]
fn full_worker_cooperative_finalization_order() {
    let mut worker = FullWorker::spawn("cooperative");
    worker.signal(libc::SIGTERM);
    worker.finish_cooperative("Cause:Sigterm");
    let expected = [
        "Cause:Sigterm",
        "GracefulRequestObserved:count=1",
        "LeaderReaped",
        "BoundaryCandidate",
        "BoundaryEmptyProofEstablished:count=1",
        "UnitUnrefAttempted:count=1",
        "PamCloseStarted",
        "PamCloseCompleted",
        "PamDropped",
        "VtReleased",
        "WorkerReturning",
    ];
    let positions: Vec<_> = expected
        .iter()
        .map(|expected| {
            worker
                .events
                .iter()
                .position(|event| event == expected)
                .unwrap()
        })
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

fn assert_no_post_cancel_launch(worker: &FullWorker) {
    worker.assert_event_absent("CommitExecCalled");
    worker.assert_event_absent("Running");
}

fn run_barrier_a() {
    let mut worker = FullWorker::spawn_barrier("barrier-a");
    worker.expect_preparing();
    worker.expect("PhaseReached:PendingHandoffBeforeScope");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("PendingHandoffBeforeScope");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.finish_cancelled_launch();
    worker.assert_event_absent("ScopePrepared");
    worker.assert_event_absent("PinAcquired");
    worker.assert_event_absent("PayloadScopePreparedSent");
    worker.assert_event_absent("PayloadScopeReleaseRequested");
    assert_no_post_cancel_launch(&worker);
}

fn reach_barrier_b(mode: &str) -> FullWorker {
    let mut worker = FullWorker::spawn_barrier(mode);
    worker.expect_preparing();
    worker.expect("ScopePrepared");
    worker.expect("PinAcquired");
    worker.expect("PayloadScopePreparedSent");
    worker.expect("PhaseReached:ScopePinnedBeforeAck");
    let _ = worker.expect_prepared();
    worker
}

fn run_barrier_b() {
    let mut worker = reach_barrier_b("barrier-b");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("ScopePinnedBeforeAck");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.answer_release(false);
    worker.expect("PayloadScopeReleasedReceived");
    worker.expect("UnitUnrefAttempted:count=1");
    worker.finish_cancelled_launch();
    worker.assert_event_absent("PayloadScopeAcknowledged");
    assert_no_post_cancel_launch(&worker);
}

fn reach_barrier_c(mode: &str) -> FullWorker {
    let mut worker = FullWorker::spawn_barrier(mode);
    worker.expect_preparing();
    worker.expect("ScopePrepared");
    worker.expect("PinAcquired");
    worker.expect("PayloadScopePreparedSent");
    let (registration_nonce, _) = worker.expect_prepared();
    worker.acknowledge_scope(&registration_nonce);
    worker.expect("PayloadScopeAcknowledged");
    worker.expect("PhaseReached:AckReceivedBeforeCommitExec");
    worker
}

fn run_barrier_c_released(duplicate_signal: bool) {
    let mut worker = reach_barrier_c("barrier-c-released");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("AckReceivedBeforeCommitExec");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    if duplicate_signal {
        worker.signal(libc::SIGHUP);
    }
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.answer_release(false);
    worker.expect("PayloadScopeReleasedReceived");
    worker.expect("UnitUnrefAttempted:count=1");
    worker.finish_cancelled_launch();
    assert_no_post_cancel_launch(&worker);
    assert_eq!(
        worker
            .events
            .iter()
            .filter(|event| event.starts_with("ProbeAbortRequested"))
            .count(),
        1
    );
    assert_eq!(
        worker
            .events
            .iter()
            .filter(|event| event.starts_with("LaunchCancellationSignal"))
            .count(),
        1
    );
}

#[test]
fn full_worker_signal_before_scope_prevents_scope_and_commit() {
    run_barrier_a();
}

#[test]
fn full_worker_signal_after_pin_before_ack_prevents_commit() {
    run_barrier_b();
}

#[test]
fn full_worker_signal_after_ack_before_commit_requests_release() {
    run_barrier_c_released(false);
}

#[test]
fn full_worker_recovery_after_ack_before_commit_preserves_identity() {
    let mut worker = reach_barrier_c("barrier-c-recovery");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("AckReceivedBeforeCommitExec");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.answer_release(true);
    worker.expect("PayloadScopeRecoveryRequiredReceived");
    worker.expect("PreStartedRecoveryHeld");
    worker.assert_process_alive(worker.child.id());
    worker.assert_event_absent("UnitUnrefAttempted");
    worker.assert_event_absent("PamClose");
    worker.assert_event_absent("VtReleased");
    worker.assert_event_absent("WorkerReturning");
    assert_no_post_cancel_launch(&worker);
}

#[test]
fn full_worker_duplicate_signals_before_commit_are_idempotent() {
    run_barrier_c_released(true);
}

#[test]
fn full_worker_precommit_disappearance_releases_all_ownership() {
    let mut worker = reach_barrier_c("barrier-c-disappearance");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("AckReceivedBeforeCommitExec");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("OriginalCgroupAbsent");
    worker.expect("CleanupResolveByInvocation:count=1");
    worker.expect("CleanupPropertiesValidated:count=1");
    worker.expect("CleanupResolveByInvocation:count=2");
    worker.expect("CleanupPropertiesValidated:count=2");
    worker.expect("PreCommitDisappearanceProofEstablished");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.answer_release(false);
    worker.expect("PayloadScopeReleasedReceived");
    worker.expect("UnitUnrefAttempted:count=1");
    worker.finish_cancelled_launch();
    assert_no_post_cancel_launch(&worker);
}

#[test]
fn real_launcher_stdin_eof_is_benign_and_dedicated_ack_allows_commit() {
    let launcher = WorkerSessionLauncher::new(
        env!("CARGO_BIN_EXE_fixture-full-worker").into(),
        "/fixture/session-child".into(),
        "/fixture/session-probe".into(),
        HARNESS_TIMEOUT,
        vec![(
            "NIRALIS_FULL_WORKER_FIXTURE_MODE".into(),
            "launcher-channel".into(),
        )],
    )
    .unwrap();
    let request = SessionRequest {
        username: "fixture-user".into(),
        session: SessionInfo {
            id: "niri".into(),
            name: "Niri".into(),
            kind: SessionKind::Wayland,
        },
    };
    let plan = SessionExecPlan {
        source_path: b"/fixture.desktop".to_vec(),
        executable: b"/bin/true".to_vec(),
        argv: vec![b"true".to_vec()],
    };
    let (started, _runtime_id) = launcher
        .start_pam_session_for_test(
            request.clone(),
            plan,
            "niralis-fixture".into(),
            WorkerSecret::new("fixture-secret".into()),
        )
        .unwrap();
    assert_eq!(started.username, request.username);
    assert_eq!(started.session, request.session);
}

#[test]
fn full_worker_supervisor_disconnect_while_waiting_for_ack() {
    let mut worker = reach_barrier_b("barrier-b");
    worker.disconnect_supervisor();
    worker.continue_phase("ScopePinnedBeforeAck");
    worker.expect("LaunchSupervisorDisconnected");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.expect_release_ready();
    worker.expect("PayloadScopeRecoveryRequiredReceived");
    worker.expect("PreStartedRecoveryHeld");
    worker.assert_process_alive(worker.child.id());
    worker.assert_event_absent("UnitUnrefAttempted");
    assert_no_post_cancel_launch(&worker);
}

#[test]
fn phase_gate_is_not_runtime_selectable() {
    let cargo = include_str!("../Cargo.toml");
    let production_main = include_str!("../src/main.rs");
    let runtime = include_str!("../src/runtime.rs");
    let install = include_str!("../../../scripts/install-local.sh");
    let protocol = include_str!("../../niralis-session/src/protocol.rs");
    assert!(cargo.contains("required-features = [\"worker-test-fixtures\"]"));
    assert!(!cargo.contains("default = [\"worker-test-fixtures\"]"));
    assert!(!install.contains("worker-test-fixtures"));
    assert!(!production_main.contains("test-mode"));
    assert!(!production_main.contains("NIRALIS_TEST_PHASE"));
    assert!(!runtime.contains("NIRALIS_TEST_PHASE"));
    assert!(!protocol.contains("WorkerLaunchPhase"));
    assert_eq!(niralis_session::WORKER_PROTOCOL_VERSION, 12);
    assert_eq!(niralis_session::WORKER_CONTROL_PROTOCOL_VERSION, 3);
    assert_eq!(niralis_session_worker::SESSION_CHILD_PROTOCOL_VERSION, 9);
    assert_eq!(niralis_session_worker::SESSION_EXEC_PROBE_VERSION, 2);
}

#[test]
fn probe_abort_and_reap_exactly_once_at_barrier_a() {
    run_barrier_a();
}

#[test]
fn probe_abort_and_reap_exactly_once_at_barrier_b() {
    run_barrier_b();
}

#[test]
fn probe_abort_and_reap_exactly_once_at_barrier_c() {
    run_barrier_c_released(false);
}
