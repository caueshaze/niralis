use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use niralis_auth::{
    AuthError, AuthSessionError, AuthenticatedTransaction, AuthenticatedUser, Authenticator,
    PamSessionEnvironment, PamUnixPath, SeatId, VirtualTerminalId,
};

use crate::identity::{
    GroupResolutionError, SupplementaryGroupsResolver, UnixIdentity, UnixIdentityResolver,
};
use crate::isolation::{CapabilityState, PostDropIsolationProof};
use crate::logind::{
    LogindSessionId as ResolvedLogindSessionId, LogindSessionIdentity, LogindSessionResolver,
};
use crate::payload_scope::{
    AuthoritativePayloadScope, PayloadBoundaryObserver, PayloadScopeError, PayloadScopeManager,
};
use crate::privilege_drop::AppliedCredentials;
use crate::runtime::{
    run_worker_process_with_dependencies_and_signals, LaunchPhaseGate, StubRuntimeDirValidator,
    WorkerAuthenticatorFactory, WorkerDependencies, WorkerLaunchPhase,
};
use crate::session_child::{
    PendingExecHandoff, SessionChildError, SessionChildExpectation, SessionChildReport,
    SessionChildRunner, SessionChildRunnerFactory,
};
use crate::{
    BoundaryEmptyProof, LeaderExit, LogindError, PamSelinuxExecContext, SelinuxContextManager,
    SelinuxError, VirtualTerminalAllocator, VirtualTerminalError, VirtualTerminalLease,
    WorkerSignalFd,
};

static HARNESS: OnceLock<Mutex<std::os::unix::net::UnixStream>> = OnceLock::new();
static HARNESS_COMMANDS: OnceLock<Mutex<BufReader<std::os::unix::net::UnixStream>>> =
    OnceLock::new();

pub fn emit_fixture_event(event: &str) {
    if event.len() > 192 || event.as_bytes().contains(&b'\n') {
        return;
    }
    if let Some(stream) = HARNESS.get() {
        if let Ok(mut stream) = stream.lock() {
            let _ = stream.write_all(event.as_bytes());
            let _ = stream.write_all(b"\n");
            let _ = stream.flush();
        }
    }
}

pub fn run_full_worker_fixture(
    mode: &str,
    harness_fd: RawFd,
    signals: &WorkerSignalFd,
) -> Result<(), niralis_session::SessionError> {
    let harness = unsafe { std::os::unix::net::UnixStream::from_raw_fd(harness_fd) };
    let commands = harness
        .try_clone()
        .map_err(|_| niralis_session::SessionError::WorkerIoFailed)?;
    let _ = HARNESS.set(Mutex::new(harness));
    let _ = HARNESS_COMMANDS.set(Mutex::new(BufReader::new(commands)));
    emit_fixture_event("BootstrapEntered");
    emit_fixture_event("SignalMaskInstalled");
    let signal_flags = unsafe { libc::fcntl(signals.as_raw_fd(), libc::F_GETFD) };
    if signal_flags >= 0 && signal_flags & libc::FD_CLOEXEC != 0 {
        emit_fixture_event("SignalFdCloexec");
    }
    crate::runtime::set_fixture_grace_period(Duration::from_millis(250));
    crate::runtime::authorize_fixture_launch_watchdog();
    crate::runtime::set_fixture_control_uid(unsafe { libc::getuid() });

    let mode = match mode {
        "cooperative" => FixtureMode::Cooperative,
        "non-cooperative" => FixtureMode::NonCooperative,
        "barrier-a" => FixtureMode::BarrierA,
        "barrier-b" => FixtureMode::BarrierB,
        "barrier-c-released" => FixtureMode::BarrierCReleased,
        "barrier-c-recovery" => FixtureMode::BarrierCRecovery,
        "invalidation-before-kill" => FixtureMode::InvalidationBeforeKill,
        "replacement-during-proof" => FixtureMode::ReplacementDuringProof,
        "bus-loss-before-kill" => FixtureMode::BusLossBeforeKill,
        _ => return Err(niralis_session::SessionError::WorkerRejected),
    };
    let state = Arc::new(FixtureState::new(mode)?);
    let auth = FixtureAuthenticatorFactory;
    let identity = FixtureIdentityResolver;
    let groups = FixtureGroupsResolver;
    let child = FixtureChildFactory(state.clone());
    let logind = FixtureLogind::default();
    let vt = FixtureVtAllocator;
    let selinux = FixtureSelinux;
    let scope = FixtureScopeManager(state.clone());
    let phase_gate = FixturePhaseGate(state);
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let result = run_worker_process_with_dependencies_and_signals(
        &mut stdin,
        &mut stdout,
        signals,
        WorkerDependencies {
            authenticator_factory: &auth,
            identity_resolver: &identity,
            supplementary_groups_resolver: &groups,
            session_child_runner_factory: &child,
            logind_resolver: &logind,
            virtual_terminal_allocator: &vt,
            runtime_dir_validator: &StubRuntimeDirValidator,
            selinux_context_manager: &selinux,
            payload_scope_manager: &scope,
            launch_phase_gate: &phase_gate,
        },
    );
    if result.is_err() {
        emit_fixture_event("WorkerReturning");
    }
    result
}

fn read_fixture_command(expected: &str) -> bool {
    let Some(commands) = HARNESS_COMMANDS.get() else {
        return false;
    };
    let Ok(mut commands) = commands.lock() else {
        return false;
    };
    let mut frame = Vec::new();
    let Ok(count) = commands.read_until(b'\n', &mut frame) else {
        return false;
    };
    if count == 0 || frame.len() > 64 || frame.pop() != Some(b'\n') {
        return false;
    }
    frame == expected.as_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureMode {
    Cooperative,
    NonCooperative,
    BarrierA,
    BarrierB,
    BarrierCReleased,
    BarrierCRecovery,
    InvalidationBeforeKill,
    ReplacementDuringProof,
    BusLossBeforeKill,
}

impl FixtureMode {
    fn barrier(self) -> Option<WorkerLaunchPhase> {
        match self {
            Self::BarrierA => Some(WorkerLaunchPhase::PendingHandoffBeforeScope),
            Self::BarrierB => Some(WorkerLaunchPhase::ScopePinnedBeforeAck),
            Self::BarrierCReleased | Self::BarrierCRecovery => {
                Some(WorkerLaunchPhase::AckReceivedBeforeCommitExec)
            }
            Self::Cooperative
            | Self::NonCooperative
            | Self::InvalidationBeforeKill
            | Self::ReplacementDuringProof
            | Self::BusLossBeforeKill => None,
        }
    }

    fn requires_registration(self) -> bool {
        self.barrier().is_some()
    }
}

struct FixtureState {
    mode: FixtureMode,
    pid: Mutex<Option<u32>>,
    pidfd: Mutex<Option<OwnedFd>>,
    command: Mutex<Option<OwnedFd>>,
    boundary: OwnedFd,
    terminal: AtomicBool,
    reaped: AtomicBool,
    kill_count: AtomicUsize,
    proof_count: AtomicUsize,
    unref_count: AtomicUsize,
    commit_count: AtomicUsize,
    abort_count: AtomicUsize,
    cleanup_count: AtomicUsize,
}

impl FixtureState {
    fn new(mode: FixtureMode) -> Result<Self, niralis_session::SessionError> {
        let boundary = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if boundary < 0 {
            return Err(niralis_session::SessionError::WorkerIoFailed);
        }
        Ok(Self {
            mode,
            pid: Mutex::new(None),
            pidfd: Mutex::new(None),
            command: Mutex::new(None),
            boundary: unsafe { OwnedFd::from_raw_fd(boundary) },
            terminal: AtomicBool::new(false),
            reaped: AtomicBool::new(false),
            kill_count: AtomicUsize::new(0),
            proof_count: AtomicUsize::new(0),
            unref_count: AtomicUsize::new(0),
            commit_count: AtomicUsize::new(0),
            abort_count: AtomicUsize::new(0),
            cleanup_count: AtomicUsize::new(0),
        })
    }
}

struct FixturePhaseGate(Arc<FixtureState>);

impl LaunchPhaseGate for FixturePhaseGate {
    fn reached(&self, phase: WorkerLaunchPhase) -> Result<(), niralis_session::SessionError> {
        if self.0.mode.barrier() != Some(phase) {
            return Ok(());
        }
        let name = launch_phase_name(phase);
        emit_fixture_event(&format!("PhaseReached:{name}"));
        read_fixture_command(&format!("ContinuePhase:{name}"))
            .then_some(())
            .ok_or(niralis_session::SessionError::WorkerIoFailed)
    }
}

fn launch_phase_name(phase: WorkerLaunchPhase) -> &'static str {
    match phase {
        WorkerLaunchPhase::PendingHandoffBeforeScope => "PendingHandoffBeforeScope",
        WorkerLaunchPhase::ScopePinnedBeforeAck => "ScopePinnedBeforeAck",
        WorkerLaunchPhase::AckReceivedBeforeCommitExec => "AckReceivedBeforeCommitExec",
    }
}

struct FixtureAuthenticatorFactory;
impl WorkerAuthenticatorFactory for FixtureAuthenticatorFactory {
    fn build(&self, _: &str) -> Box<dyn Authenticator> {
        Box::new(FixtureAuthenticator)
    }
}
struct FixtureAuthenticator;
impl Authenticator for FixtureAuthenticator {
    fn authenticate(
        &self,
        username: &str,
        _: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError> {
        Ok(Box::new(FixtureTransaction {
            user: AuthenticatedUser {
                username: "fixture-user".into(),
                display_name: username.into(),
            },
            closed: false,
        }))
    }
}
struct FixtureTransaction {
    user: AuthenticatedUser,
    closed: bool,
}
impl AuthenticatedTransaction for FixtureTransaction {
    fn user(&self) -> &AuthenticatedUser {
        &self.user
    }
    fn open_session(
        &mut self,
        _: &niralis_auth::PamSessionMetadata,
    ) -> Result<(), AuthSessionError> {
        emit_fixture_event("PamOpened");
        Ok(())
    }
    fn session_environment(&mut self) -> Result<PamSessionEnvironment, AuthSessionError> {
        Ok(PamSessionEnvironment {
            session_id: "fixture-session".into(),
            runtime_dir: PamUnixPath::new(b"/tmp/niralis-fixture-runtime".to_vec())?,
            imported_locale: Vec::new(),
        })
    }
    fn close_session(&mut self) -> Result<(), AuthSessionError> {
        emit_fixture_event("PamCloseStarted");
        self.closed = true;
        emit_fixture_event("PamCloseCompleted");
        Ok(())
    }
}
impl Drop for FixtureTransaction {
    fn drop(&mut self) {
        if !self.closed {
            emit_fixture_event("PamCloseStarted");
            self.closed = true;
            emit_fixture_event("PamCloseCompleted");
        }
        emit_fixture_event("PamDropped");
    }
}

struct FixtureIdentityResolver;
impl UnixIdentityResolver for FixtureIdentityResolver {
    fn resolve(&self, _: &str) -> Result<UnixIdentity, crate::IdentityError> {
        Ok(UnixIdentity {
            username: "fixture-user".into(),
            uid: 1000,
            gid: 1000,
            home: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    }
}
struct FixtureGroupsResolver;
impl SupplementaryGroupsResolver for FixtureGroupsResolver {
    fn resolve(&self, _: &UnixIdentity) -> Result<Vec<u32>, GroupResolutionError> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct FixtureLogind(AtomicUsize);
impl LogindSessionResolver for FixtureLogind {
    fn resolve_by_pid(&self, _: u32) -> Result<Option<LogindSessionIdentity>, LogindError> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            return Ok(None);
        }
        Ok(Some(fixture_logind_identity()))
    }
    fn resolve_by_id(
        &self,
        _: &ResolvedLogindSessionId,
    ) -> Result<Option<LogindSessionIdentity>, LogindError> {
        Ok(Some(fixture_logind_identity()))
    }
}
fn fixture_logind_identity() -> LogindSessionIdentity {
    LogindSessionIdentity {
        id: ResolvedLogindSessionId::new("fixture-session".into()).unwrap(),
        uid: 1000,
        session_type: "wayland".into(),
        class: "user".into(),
        desktop: Some("niri".into()),
        seat: Some("seat0".into()),
        vtnr: Some(1),
    }
}

struct FixtureVtAllocator;
impl VirtualTerminalAllocator for FixtureVtAllocator {
    fn allocate(
        &self,
        seat: &SeatId,
    ) -> Result<Box<dyn VirtualTerminalLease>, VirtualTerminalError> {
        emit_fixture_event("VtAcquired");
        Ok(Box::new(FixtureVtLease {
            seat: seat.clone(),
            released: false,
        }))
    }
}
struct FixtureVtLease {
    seat: SeatId,
    released: bool,
}
impl VirtualTerminalLease for FixtureVtLease {
    fn seat(&self) -> &SeatId {
        &self.seat
    }
    fn vtnr(&self) -> VirtualTerminalId {
        VirtualTerminalId::new(1).unwrap()
    }
    fn duplicate_terminal_fd(&self) -> Result<OwnedFd, VirtualTerminalError> {
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            Err(VirtualTerminalError::OperationFailed)
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
    fn activate(&mut self, _: Duration) -> Result<(), VirtualTerminalError> {
        Ok(())
    }
    fn release(&mut self) -> Result<(), VirtualTerminalError> {
        if !self.released {
            self.released = true;
            emit_fixture_event("VtReleased");
        }
        Ok(())
    }
}

struct FixtureSelinux;
impl SelinuxContextManager for FixtureSelinux {
    fn capture_pending(&self) -> Result<Option<PamSelinuxExecContext>, SelinuxError> {
        Ok(None)
    }
    fn clear_pending(&self) -> Result<(), SelinuxError> {
        Ok(())
    }
    fn apply_pending(&self, _: &PamSelinuxExecContext) -> Result<(), SelinuxError> {
        Ok(())
    }
    fn context_for_pid(&self, _: u32) -> Result<PamSelinuxExecContext, SelinuxError> {
        Err(SelinuxError::QueryFailed)
    }
}

struct FixtureChildFactory(Arc<FixtureState>);
impl SessionChildRunnerFactory for FixtureChildFactory {
    fn build(&self, _: &std::path::Path) -> Result<Box<dyn SessionChildRunner>, SessionChildError> {
        Ok(Box::new(FixtureChildRunner(self.0.clone())))
    }
}
struct FixtureChildRunner(Arc<FixtureState>);
struct FixturePending {
    state: Arc<FixtureState>,
    report: SessionChildReport,
    pidfd: Option<OwnedFd>,
    completed: bool,
}

impl SessionChildRunner for FixtureChildRunner {
    fn run_child_until_ready(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<Box<dyn PendingExecHandoff>, SessionChildError> {
        let (command_read, command_write) = pipe()?;
        let (ready_read, ready_write) = pipe()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(SessionChildError::IoFailed);
        }
        if pid == 0 {
            drop(command_write);
            drop(ready_read);
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                libc::setsid();
            }
            let signal_state_clean = crate::termination::restore_payload_signal_state().is_ok()
                && [libc::SIGTERM, libc::SIGINT, libc::SIGHUP]
                    .into_iter()
                    .all(signal_has_default_disposition);
            for fd in 3..1024 {
                if fd != command_read.as_raw_fd() && fd != ready_write.as_raw_fd() {
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
            let fd_hygiene = (3..1024).all(|fd| {
                fd == command_read.as_raw_fd()
                    || fd == ready_write.as_raw_fd()
                    || unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1
            });
            let flags = [u8::from(signal_state_clean), u8::from(fd_hygiene)];
            unsafe {
                libc::write(ready_write.as_raw_fd(), flags.as_ptr().cast(), flags.len());
            }
            let mut byte = 0_u8;
            unsafe {
                libc::read(command_read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
            }
            unsafe { libc::_exit(0) }
        }
        drop(command_read);
        drop(ready_write);
        let mut flags = [0_u8; 2];
        if unsafe { libc::read(ready_read.as_raw_fd(), flags.as_mut_ptr().cast(), 2) } != 2 {
            return Err(SessionChildError::IoFailed);
        }
        if flags[0] == 1 {
            emit_fixture_event("PayloadSignalMaskRestored");
        }
        if flags[1] == 1 {
            emit_fixture_event("PayloadFdHygieneVerified");
        }
        let pid = pid as u32;
        emit_fixture_event(&format!("LeaderPid:{pid}"));
        let pidfd = open_pidfd(pid)?;
        *self.0.pid.lock().map_err(|_| SessionChildError::IoFailed)? = Some(pid);
        *self
            .0
            .command
            .lock()
            .map_err(|_| SessionChildError::IoFailed)? = Some(command_write);
        let report = fixture_report(expectation, pid);
        emit_fixture_event("PendingExecHandoffReady");
        Ok(Box::new(FixturePending {
            state: self.0.clone(),
            report,
            pidfd: Some(pidfd),
            completed: false,
        }))
    }
    fn poll_child(&self) -> Result<Option<std::process::ExitStatus>, SessionChildError> {
        let pid = self
            .0
            .pid
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?
            .ok_or(SessionChildError::IoFailed)?;
        let mut raw = 0;
        let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut raw, libc::WNOHANG) };
        if result == 0 {
            return Ok(None);
        }
        if result != pid as libc::pid_t {
            return Err(SessionChildError::IoFailed);
        }
        if self.0.reaped.swap(true, Ordering::SeqCst) {
            return Err(SessionChildError::IoFailed);
        }
        emit_fixture_event("LeaderReaped");
        Ok(Some(std::process::ExitStatus::from_raw(raw)))
    }
    fn authoritative_pidfd(&self) -> RawFd {
        self.0
            .pidfd
            .lock()
            .ok()
            .and_then(|fd| fd.as_ref().map(AsRawFd::as_raw_fd))
            .unwrap_or(-1)
    }
}
impl PendingExecHandoff for FixturePending {
    fn report(&self) -> &SessionChildReport {
        &self.report
    }
    fn authoritative_pidfd(&self) -> RawFd {
        self.pidfd.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
    fn commit_exec(mut self: Box<Self>) -> Result<SessionChildReport, SessionChildError> {
        let count = self.state.commit_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("CommitExecCalled:count={count}"));
        *self
            .state
            .pidfd
            .lock()
            .map_err(|_| SessionChildError::IoFailed)? = self.pidfd.take();
        self.completed = true;
        Ok(self.report.clone())
    }
    fn abort(mut self: Box<Self>) -> Result<(), SessionChildError> {
        let count = self.state.abort_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("ProbeAbortRequested:count={count}"));
        drop(
            self.state
                .command
                .lock()
                .map_err(|_| SessionChildError::IoFailed)?
                .take(),
        );
        let pid = self
            .state
            .pid
            .lock()
            .map_err(|_| SessionChildError::IoFailed)?
            .ok_or(SessionChildError::IoFailed)?;
        let mut raw = 0;
        if unsafe { libc::waitpid(pid as libc::pid_t, &mut raw, 0) } != pid as libc::pid_t {
            return Err(SessionChildError::IoFailed);
        }
        if self.state.reaped.swap(true, Ordering::SeqCst) {
            return Err(SessionChildError::IoFailed);
        }
        emit_fixture_event("ProbeReaped:count=1");
        self.pidfd.take();
        self.completed = true;
        Ok(())
    }
}
impl Drop for FixturePending {
    fn drop(&mut self) {
        if !self.completed {
            if let Ok(pid) = self.state.pid.lock() {
                if let Some(pid) = *pid {
                    unsafe {
                        libc::kill(pid as libc::pid_t, libc::SIGKILL);
                        libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0);
                    }
                }
            }
        }
    }
}

struct FixtureScopeManager(Arc<FixtureState>);
impl PayloadScopeManager for FixtureScopeManager {
    fn requires_supervisor_registration(&self) -> bool {
        self.0.mode.requires_registration()
    }
    fn prepare(
        &self,
        _: &SessionChildReport,
        _: RawFd,
        expected_uid: u32,
        logind: &niralis_session::LogindSessionId,
        _: u32,
        _: u32,
        _: Instant,
    ) -> Result<Box<dyn AuthoritativePayloadScope>, PayloadScopeError> {
        emit_fixture_event("ScopePrepared");
        emit_fixture_event("PinAcquired");
        Ok(Box::new(FixtureScope {
            state: self.0.clone(),
            identity: niralis_session::PayloadScopeIdentity {
                unit_name: "niralis-payload-00000000000000000000000000000000.scope".into(),
                invocation_id: "00000000000000000000000000000000".into(),
                expected_uid,
                logind_session_id: logind.clone(),
            },
        }))
    }
}
struct FixtureScope {
    state: Arc<FixtureState>,
    identity: niralis_session::PayloadScopeIdentity,
}
impl AuthoritativePayloadScope for FixtureScope {
    fn identity(&self) -> &niralis_session::PayloadScopeIdentity {
        &self.identity
    }
    fn control_group(&self) -> &str {
        "/fixture.scope"
    }
    fn cleanup(self: Box<Self>, _: Instant) -> Result<(), PayloadScopeError> {
        let count = self.state.cleanup_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("ScopeCleanupRequested:count={count}"));
        let unref = self.state.unref_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("UnitUnrefAttempted:count={unref}"));
        Ok(())
    }
    fn cleanup_preserving_pin(&mut self, _: Instant) -> Result<(), PayloadScopeError> {
        let count = self.state.cleanup_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("ScopeCleanupRequested:count={count}"));
        emit_fixture_event("PinHeldAfterScopeCleanup");
        Ok(())
    }
    fn create_boundary_observer(
        &self,
    ) -> Result<Box<dyn PayloadBoundaryObserver>, PayloadScopeError> {
        let fd = unsafe { libc::fcntl(self.state.boundary.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            Err(PayloadScopeError::ObserverFailed)
        } else {
            Ok(Box::new(FixtureObserver(unsafe {
                OwnedFd::from_raw_fd(fd)
            })))
        }
    }
    fn request_graceful_termination(&self) -> Result<(), PayloadScopeError> {
        let count = self.state.kill_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("GracefulRequestObserved:count={count}"));
        match self.state.mode {
            FixtureMode::InvalidationBeforeKill => {
                emit_fixture_event("InvocationInvalidatedBeforeKill");
                return Err(PayloadScopeError::InvocationUnavailable);
            }
            FixtureMode::BusLossBeforeKill => {
                emit_fixture_event("SystemBusLostBeforeKill");
                return Err(PayloadScopeError::BusUnavailable);
            }
            _ => {}
        }
        if matches!(
            self.state.mode,
            FixtureMode::Cooperative | FixtureMode::ReplacementDuringProof
        ) {
            let state = self.state.clone();
            std::thread::spawn(move || {
                if !read_fixture_command("AllowPayloadExit") {
                    return;
                }
                let command = state.command.lock().ok().and_then(|mut value| value.take());
                let Some(command) = command else {
                    return;
                };
                if unsafe { libc::write(command.as_raw_fd(), b"x".as_ptr().cast(), 1) } != 1 {
                    return;
                }
                let fd = state.pidfd.lock().ok().and_then(|fd| {
                    fd.as_ref().and_then(|fd| unsafe {
                        let value = libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3);
                        (value >= 0).then(|| OwnedFd::from_raw_fd(value))
                    })
                });
                if let Some(fd) = fd {
                    let mut poll = libc::pollfd {
                        fd: fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe {
                        libc::poll(&mut poll, 1, -1);
                    }
                    if !read_fixture_command("MakeBoundaryTerminal") {
                        return;
                    }
                    state.terminal.store(true, Ordering::SeqCst);
                    let one = 1_u64;
                    unsafe {
                        libc::write(state.boundary.as_raw_fd(), (&one as *const u64).cast(), 8);
                    }
                }
            });
        }
        Ok(())
    }
    fn boundary_appears_terminal(&self) -> Result<bool, PayloadScopeError> {
        Ok(self.state.terminal.load(Ordering::SeqCst))
    }
    fn prove_empty_boundary(
        &self,
        exit: &LeaderExit,
    ) -> Result<BoundaryEmptyProof, PayloadScopeError> {
        if !self.state.terminal.load(Ordering::SeqCst) || !self.state.reaped.load(Ordering::SeqCst)
        {
            return Err(PayloadScopeError::BoundaryNotEmpty);
        }
        if self.state.mode == FixtureMode::ReplacementDuringProof {
            emit_fixture_event("InvocationReplacedDuringProof");
            return Err(PayloadScopeError::UnitReplaced);
        }
        let count = self.state.proof_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("BoundaryEmptyProofEstablished:count={count}"));
        Ok(BoundaryEmptyProof::new(
            &self.identity,
            self.control_group(),
            exit.clone(),
        ))
    }
    fn release_pin(&mut self) -> Result<(), PayloadScopeError> {
        let count = self.state.unref_count.fetch_add(1, Ordering::SeqCst) + 1;
        emit_fixture_event(&format!("UnitUnrefAttempted:count={count}"));
        Ok(())
    }
}
struct FixtureObserver(OwnedFd);
impl PayloadBoundaryObserver for FixtureObserver {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
    fn poll_events(&self) -> libc::c_short {
        libc::POLLIN
    }
    fn consume_wakeup(&mut self) -> Result<(), PayloadScopeError> {
        let mut value = 0_u64;
        (unsafe { libc::read(self.0.as_raw_fd(), (&mut value as *mut u64).cast(), 8) } == 8)
            .then_some(())
            .ok_or(PayloadScopeError::ObserverFailed)
    }
}

fn pipe() -> Result<(OwnedFd, OwnedFd), SessionChildError> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SessionChildError::IoFailed);
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}
fn open_pidfd(pid: u32) -> Result<OwnedFd, SessionChildError> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as RawFd;
    if fd < 0 {
        Err(SessionChildError::IoFailed)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn signal_has_default_disposition(signal: libc::c_int) -> bool {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    (unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) == 0 })
        && action.sa_sigaction == libc::SIG_DFL
}
fn fixture_report(expectation: SessionChildExpectation, pid: u32) -> SessionChildReport {
    let credentials = &expectation.target_credentials;
    SessionChildReport {
        canonical_username: expectation.canonical_username.clone(),
        session_id: expectation.session_id,
        child_pid: pid,
        applied_credentials: AppliedCredentials {
            uid: credentials.uid,
            gid: credentials.gid,
            supplementary_gids: credentials.supplementary_gids.clone(),
        },
        credential_proof: crate::session_child::SessionChildCredentialProof {
            real_uid: credentials.uid,
            effective_uid: credentials.uid,
            saved_uid: credentials.uid,
            real_gid: credentials.gid,
            effective_gid: credentials.gid,
            saved_gid: credentials.gid,
            supplementary_gids: credentials.supplementary_gids.clone(),
        },
        isolation_proof: PostDropIsolationProof {
            capabilities: CapabilityState {
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
        },
        process_identity: crate::session_child::ProcessIdentityProof {
            pid,
            sid: pid,
            pgid: pid,
        },
        runtime_environment: crate::session_child::RuntimeEnvironmentProof {
            home: expectation.runtime.home.clone(),
            user: expectation.canonical_username.clone(),
            logname: expectation.canonical_username,
            shell: expectation.runtime.shell.clone(),
            path: crate::session_child::DEFAULT_SESSION_PATH.into(),
            session_type: expectation.runtime.session_type,
            session_class: expectation.runtime.session_class,
            session_desktop: expectation.runtime.session_desktop,
            session_id: expectation.runtime.session_id,
            runtime_dir: expectation.runtime.runtime_dir,
            seat: expectation.runtime.seat,
            vtnr: expectation.runtime.vtnr,
            dbus_session_bus_address: None,
            imported_locale: Vec::new(),
            forbidden_variables_present: Vec::new(),
            user_bus_connected: true,
            cwd: expectation.runtime.home,
            exec_plan: expectation.runtime.exec_plan,
        },
        exec_probe_version: crate::session_child::SESSION_EXEC_PROBE_VERSION,
        terminal_proof: expectation.terminal.map(|terminal| {
            crate::session_child::SessionChildTerminalProof {
                seat: terminal.seat,
                vtnr: terminal.vtnr,
                fd: terminal.fd,
                device_major: 4,
                device_minor: terminal.vtnr,
                controlling_sid: pid,
                foreground_pgid: pid,
            }
        }),
    }
}
