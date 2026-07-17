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
    harness_fd: Option<RawFd>,
    supervisor_fd: RawFd,
    signals: &WorkerSignalFd,
) -> Result<(), niralis_session::SessionError> {
    if let Some(harness_fd) = harness_fd {
        let harness = unsafe { std::os::unix::net::UnixStream::from_raw_fd(harness_fd) };
        let commands = harness
            .try_clone()
            .map_err(|_| niralis_session::SessionError::WorkerIoFailed)?;
        let _ = HARNESS.set(Mutex::new(harness));
        let _ = HARNESS_COMMANDS.set(Mutex::new(BufReader::new(commands)));
    }
    emit_fixture_event("BootstrapEntered");
    emit_fixture_event("SignalMaskInstalled");
    let signal_flags = unsafe { libc::fcntl(signals.as_raw_fd(), libc::F_GETFD) };
    if signal_flags >= 0 && signal_flags & libc::FD_CLOEXEC != 0 {
        emit_fixture_event("SignalFdCloexec");
    }
    let supervisor_flags = unsafe { libc::fcntl(supervisor_fd, libc::F_GETFD) };
    if supervisor_flags >= 0 && supervisor_flags & libc::FD_CLOEXEC != 0 {
        emit_fixture_event("SupervisorFdCloexec");
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
        "barrier-c-disappearance" => FixtureMode::BarrierCDisappearance,
        "launcher-channel" => FixtureMode::LauncherChannel,
        "invalidation-before-kill" => FixtureMode::InvalidationBeforeKill,
        "replacement-during-proof" => FixtureMode::ReplacementDuringProof,
        "bus-loss-before-kill" => FixtureMode::BusLossBeforeKill,
        "leader-exit-remaining-member" => FixtureMode::LeaderExitRemainingMember,
        "forced-deadline" => FixtureMode::ForcedDeadline,
        "replacement-before-forced-kill" => FixtureMode::ReplacementBeforeForcedKill,
        "bus-loss-after-forced-kill" => FixtureMode::BusLossAfterForcedKill,
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
        supervisor_fd,
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
    BarrierCDisappearance,
    LauncherChannel,
    InvalidationBeforeKill,
    ReplacementDuringProof,
    BusLossBeforeKill,
    LeaderExitRemainingMember,
    ForcedDeadline,
    ReplacementBeforeForcedKill,
    BusLossAfterForcedKill,
}

impl FixtureMode {
    fn barrier(self) -> Option<WorkerLaunchPhase> {
        match self {
            Self::BarrierA => Some(WorkerLaunchPhase::PendingHandoffBeforeScope),
            Self::BarrierB => Some(WorkerLaunchPhase::ScopePinnedBeforeAck),
            Self::BarrierCReleased | Self::BarrierCRecovery | Self::BarrierCDisappearance => {
                Some(WorkerLaunchPhase::AckReceivedBeforeCommitExec)
            }
            Self::Cooperative
            | Self::NonCooperative
            | Self::InvalidationBeforeKill
            | Self::ReplacementDuringProof
            | Self::BusLossBeforeKill
            | Self::LeaderExitRemainingMember
            | Self::ForcedDeadline
            | Self::ReplacementBeforeForcedKill
            | Self::BusLossAfterForcedKill
            | Self::LauncherChannel => None,
        }
    }

    fn requires_registration(self) -> bool {
        self.barrier().is_some() || self == Self::LauncherChannel
    }
}

struct FixtureState {
    mode: FixtureMode,
    pid: Mutex<Option<u32>>,
    member_pid: Mutex<Option<u32>>,
    pidfd: Mutex<Option<OwnedFd>>,
    command: Mutex<Option<OwnedFd>>,
    boundary: OwnedFd,
    terminal: AtomicBool,
    reaped: AtomicBool,
    kill_count: AtomicUsize,
    forced_kill_count: AtomicUsize,
    proof_count: AtomicUsize,
    unref_count: AtomicUsize,
    commit_count: AtomicUsize,
    abort_count: AtomicUsize,
    cleanup_count: AtomicUsize,
}
