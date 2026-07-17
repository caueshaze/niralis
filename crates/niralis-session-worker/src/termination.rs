use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerTerminationSignal {
    Sigterm,
    Sigint,
    Sighup,
}

impl WorkerTerminationSignal {
    pub fn from_raw(signal: libc::c_int) -> Option<Self> {
        match signal {
            libc::SIGTERM => Some(Self::Sigterm),
            libc::SIGINT => Some(Self::Sigint),
            libc::SIGHUP => Some(Self::Sighup),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaderExit {
    ExitedZero,
    ExitedNonZero(i32),
    KilledBySignal(i32),
    Other(i32),
}

impl LeaderExit {
    pub fn from_status(status: std::process::ExitStatus) -> Self {
        if let Some(code) = status.code() {
            if code == 0 {
                Self::ExitedZero
            } else {
                Self::ExitedNonZero(code)
            }
        } else if let Some(signal) = status.signal() {
            Self::KilledBySignal(signal)
        } else {
            Self::Other(status.into_raw())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationCause {
    InternalTerminateRequest,
    WorkerSignal(WorkerTerminationSignal),
    SupervisorDisconnected,
    LeaderExited(LeaderExit),
    RuntimeFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryTerminalObservation {
    CgroupEventRevalidated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracefulTerminationError {
    BoundaryObserver,
    ScopeOperation(crate::payload_scope::PayloadScopeError),
    Timer,
    Poll,
    LeaderReap,
    Signal,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryReason {
    BoundaryIdentityChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracefulTerminationOutcome {
    BoundaryTerminalCandidate {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        observation: BoundaryTerminalObservation,
    },
    DeadlineExpired {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
    },
    InfrastructureFailure {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        error: GracefulTerminationError,
    },
    RecoveryRequired {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        reason: RecoveryReason,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct BoundaryEmptyProof {
    unit_name: String,
    invocation_id: String,
    control_group: String,
    leader_exit: LeaderExit,
}

impl BoundaryEmptyProof {
    pub(crate) fn new(
        identity: &niralis_session::PayloadScopeIdentity,
        control_group: &str,
        leader_exit: LeaderExit,
    ) -> Self {
        Self {
            unit_name: identity.unit_name.clone(),
            invocation_id: identity.invocation_id.clone(),
            control_group: control_group.to_owned(),
            leader_exit,
        }
    }

    pub fn leader_exit(&self) -> &LeaderExit {
        &self.leader_exit
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum GracefulFinalizationDecision {
    FinalizeCooperative(BoundaryEmptyProof),
    NeedsEscalation {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
    },
    RecoveryRequired {
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
        reason: RecoveryReason,
    },
}

pub fn consume_graceful_outcome(
    outcome: GracefulTerminationOutcome,
    scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
) -> GracefulFinalizationDecision {
    match outcome {
        GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause,
            leader_exit: Some(leader_exit),
            ..
        } => match scope.prove_empty_boundary(&leader_exit) {
            Ok(proof) => GracefulFinalizationDecision::FinalizeCooperative(proof),
            Err(crate::payload_scope::PayloadScopeError::UnitReplaced) => {
                GracefulFinalizationDecision::RecoveryRequired {
                    cause,
                    leader_exit: Some(leader_exit),
                    reason: RecoveryReason::BoundaryIdentityChanged,
                }
            }
            Err(_) => GracefulFinalizationDecision::NeedsEscalation {
                cause,
                leader_exit: Some(leader_exit),
            },
        },
        GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause,
            leader_exit: None,
            ..
        } => GracefulFinalizationDecision::NeedsEscalation {
            cause,
            leader_exit: None,
        },
        GracefulTerminationOutcome::DeadlineExpired { cause, leader_exit }
        | GracefulTerminationOutcome::InfrastructureFailure {
            cause, leader_exit, ..
        } => GracefulFinalizationDecision::NeedsEscalation { cause, leader_exit },
        GracefulTerminationOutcome::RecoveryRequired {
            cause,
            leader_exit,
            reason,
        } => GracefulFinalizationDecision::RecoveryRequired {
            cause,
            leader_exit,
            reason,
        },
    }
}

pub struct GracefulTerminationCoordinator {
    cause: Option<TerminationCause>,
    leader_exit: Option<LeaderExit>,
    timer: GraceTimerFd,
    requested: bool,
    finished: bool,
}

impl GracefulTerminationCoordinator {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            cause: None,
            leader_exit: None,
            timer: GraceTimerFd::new()?,
            requested: false,
            finished: false,
        })
    }
    pub fn timer_fd(&self) -> RawFd {
        self.timer.as_raw_fd()
    }
    pub fn cause(&self) -> Option<&TerminationCause> {
        self.cause.as_ref()
    }
    pub fn record_leader_exit(&mut self, exit: LeaderExit) {
        if self.leader_exit.is_none() {
            self.leader_exit = Some(exit);
        }
    }
    pub fn begin(
        &mut self,
        cause: TerminationCause,
        duration: Duration,
        scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
    ) -> Result<
        Option<Box<dyn crate::payload_scope::PayloadBoundaryObserver>>,
        GracefulTerminationOutcome,
    > {
        if self.requested {
            return Ok(None);
        }
        self.cause = Some(cause);
        let observer = scope
            .create_boundary_observer()
            .map_err(|error| self.scope_error(error))?;
        scope
            .request_graceful_termination()
            .map_err(|error| self.scope_error(error))?;
        self.timer
            .arm_once(duration)
            .map_err(|_| self.infrastructure(GracefulTerminationError::Timer))?;
        self.requested = true;
        Ok(Some(observer))
    }
    pub fn boundary_candidate(
        &mut self,
        observation: BoundaryTerminalObservation,
    ) -> GracefulTerminationOutcome {
        self.finished = true;
        GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: self
                .cause
                .clone()
                .unwrap_or(TerminationCause::RuntimeFailure),
            leader_exit: self.leader_exit.clone(),
            observation,
        }
    }
    pub fn deadline_expired(&mut self) -> GracefulTerminationOutcome {
        self.finished = true;
        GracefulTerminationOutcome::DeadlineExpired {
            cause: self
                .cause
                .clone()
                .unwrap_or(TerminationCause::RuntimeFailure),
            leader_exit: self.leader_exit.clone(),
        }
    }
    pub fn infrastructure(
        &mut self,
        error: GracefulTerminationError,
    ) -> GracefulTerminationOutcome {
        self.finished = true;
        GracefulTerminationOutcome::InfrastructureFailure {
            cause: self
                .cause
                .clone()
                .unwrap_or(TerminationCause::RuntimeFailure),
            leader_exit: self.leader_exit.clone(),
            error,
        }
    }
    pub fn scope_error(
        &mut self,
        error: crate::payload_scope::PayloadScopeError,
    ) -> GracefulTerminationOutcome {
        if error == crate::payload_scope::PayloadScopeError::UnitReplaced {
            self.finished = true;
            GracefulTerminationOutcome::RecoveryRequired {
                cause: self
                    .cause
                    .clone()
                    .unwrap_or(TerminationCause::RuntimeFailure),
                leader_exit: self.leader_exit.clone(),
                reason: RecoveryReason::BoundaryIdentityChanged,
            }
        } else {
            self.infrastructure(GracefulTerminationError::ScopeOperation(error))
        }
    }
    pub fn consume_deadline(&self) -> io::Result<bool> {
        self.timer.consume()
    }
}

const SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

pub struct WorkerSignalFd {
    fd: OwnedFd,
    previous_mask: libc::sigset_t,
}

impl WorkerSignalFd {
    pub fn install() -> io::Result<Self> {
        let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigemptyset(&mut mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for signal in SIGNALS {
            if unsafe { libc::sigaddset(&mut mask, signal) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut previous_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mask_result =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous_mask) };
        if mask_result != 0 {
            return Err(io::Error::from_raw_os_error(mask_result));
        }
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if fd < 0 {
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut())
            };
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            previous_mask,
        })
    }

    pub fn read_signal(&self) -> io::Result<Option<libc::c_int>> {
        let mut info = unsafe { std::mem::zeroed::<libc::signalfd_siginfo>() };
        let read = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&mut info as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of::<libc::signalfd_siginfo>(),
            )
        };
        if read == std::mem::size_of::<libc::signalfd_siginfo>() as isize {
            let signal = info.ssi_signo as libc::c_int;
            return SIGNALS
                .contains(&signal)
                .then_some(signal)
                .map(Some)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "unexpected signalfd signal")
                });
        }
        let error = io::Error::last_os_error();
        if read < 0 && error.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error)
        }
    }
}

impl AsRawFd for WorkerSignalFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
impl Drop for WorkerSignalFd {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut())
        };
    }
}

pub fn restore_payload_signal_state() -> io::Result<()> {
    let mut empty = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigemptyset(&mut empty) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mask_result =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) };
    if mask_result != 0 {
        return Err(io::Error::from_raw_os_error(mask_result));
    }
    for signal in SIGNALS {
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = libc::SIG_DFL;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub struct GraceTimerFd(OwnedFd);
impl GraceTimerFd {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
        }
    }
    pub fn arm_once(&self, duration: Duration) -> io::Result<()> {
        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: duration.as_secs().try_into().unwrap_or(libc::time_t::MAX),
                tv_nsec: duration.subsec_nanos().into(),
            },
        };
        if unsafe { libc::timerfd_settime(self.0.as_raw_fd(), 0, &spec, std::ptr::null_mut()) } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    pub fn consume(&self) -> io::Result<bool> {
        let mut expirations = 0_u64;
        let read = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                (&mut expirations as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if read == std::mem::size_of::<u64>() as isize {
            Ok(expirations > 0)
        } else {
            let error = io::Error::last_os_error();
            if read < 0 && error.kind() == io::ErrorKind::WouldBlock {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}
impl AsRawFd for GraceTimerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub fn read_signal_fd(fd: RawFd) -> io::Result<Option<libc::c_int>> {
    let mut info = unsafe { std::mem::zeroed::<libc::signalfd_siginfo>() };
    let read = unsafe {
        libc::read(
            fd,
            (&mut info as *mut libc::signalfd_siginfo).cast(),
            std::mem::size_of::<libc::signalfd_siginfo>(),
        )
    };
    if read == std::mem::size_of::<libc::signalfd_siginfo>() as isize {
        let signal = info.ssi_signo as libc::c_int;
        return SIGNALS
            .contains(&signal)
            .then_some(signal)
            .map(Some)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unexpected signalfd signal")
            });
    }
    let error = io::Error::last_os_error();
    if read < 0 && error.kind() == io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct TestObserver(OwnedFd);
    impl crate::payload_scope::PayloadBoundaryObserver for TestObserver {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
        fn consume_wakeup(&mut self) -> Result<(), crate::payload_scope::PayloadScopeError> {
            let mut value = 0_u64;
            let read =
                unsafe { libc::read(self.0.as_raw_fd(), (&mut value as *mut u64).cast(), 8) };
            (read == 8)
                .then_some(())
                .ok_or(crate::payload_scope::PayloadScopeError::ObserverFailed)
        }
    }

    struct TestScope {
        identity: niralis_session::PayloadScopeIdentity,
        event_fd: OwnedFd,
        requests: Arc<AtomicUsize>,
        fail: Option<crate::payload_scope::PayloadScopeError>,
    }
    impl TestScope {
        fn new(fail: Option<crate::payload_scope::PayloadScopeError>) -> Self {
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            Self {
                identity: niralis_session::PayloadScopeIdentity {
                    unit_name: "niralis-payload-00000000000000000000000000000000.scope".into(),
                    invocation_id: "00000000000000000000000000000000".into(),
                    expected_uid: 1000,
                    logind_session_id: niralis_session::LogindSessionId::new("1".into()).unwrap(),
                },
                event_fd: unsafe { OwnedFd::from_raw_fd(fd) },
                requests: Arc::new(AtomicUsize::new(0)),
                fail,
            }
        }
    }
    impl crate::payload_scope::AuthoritativePayloadScope for TestScope {
        fn identity(&self) -> &niralis_session::PayloadScopeIdentity {
            &self.identity
        }
        fn control_group(&self) -> &str {
            "/test"
        }
        fn cleanup(
            self: Box<Self>,
            _: std::time::Instant,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            Ok(())
        }
        fn create_boundary_observer(
            &self,
        ) -> Result<
            Box<dyn crate::payload_scope::PayloadBoundaryObserver>,
            crate::payload_scope::PayloadScopeError,
        > {
            let fd = unsafe { libc::fcntl(self.event_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                Err(crate::payload_scope::PayloadScopeError::ObserverFailed)
            } else {
                Ok(Box::new(TestObserver(unsafe { OwnedFd::from_raw_fd(fd) })))
            }
        }
        fn request_graceful_termination(
            &self,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            self.fail.clone().map_or(Ok(()), Err)
        }
        fn prove_empty_boundary(
            &self,
            leader_exit: &LeaderExit,
        ) -> Result<BoundaryEmptyProof, crate::payload_scope::PayloadScopeError> {
            if let Some(error) = &self.fail {
                return Err(error.clone());
            }
            Ok(BoundaryEmptyProof::new(
                &self.identity,
                self.control_group(),
                leader_exit.clone(),
            ))
        }
    }

    #[test]
    fn descriptors_are_cloexec_nonblocking_and_timer_is_one_shot() {
        let timer = GraceTimerFd::new().unwrap();
        let fd_flags = unsafe { libc::fcntl(timer.as_raw_fd(), libc::F_GETFD) };
        let status_flags = unsafe { libc::fcntl(timer.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
        assert_ne!(status_flags & libc::O_NONBLOCK, 0);
        assert!(!timer.consume().unwrap());
        timer.arm_once(Duration::from_millis(1)).unwrap();
        let mut pollfd = libc::pollfd {
            fd: timer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 1000) }, 1);
        assert!(timer.consume().unwrap());
        assert!(!timer.consume().unwrap());
    }

    #[test]
    fn payload_restore_unblocks_managed_signals() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let signals = WorkerSignalFd::install().unwrap();
            assert!(signals.as_raw_fd() >= 0);
            restore_payload_signal_state().unwrap();
            let mut current = unsafe { std::mem::zeroed::<libc::sigset_t>() };
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current) };
            let clean = SIGNALS
                .iter()
                .all(|signal| unsafe { libc::sigismember(&current, *signal) } == 0);
            std::mem::forget(signals);
            unsafe { libc::_exit(if clean { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn leader_exit_is_typed_without_text_parsing() {
        assert_eq!(
            LeaderExit::from_status(std::process::ExitStatus::from_raw(0)),
            LeaderExit::ExitedZero
        );
        assert_eq!(
            LeaderExit::from_status(std::process::ExitStatus::from_raw(42 << 8)),
            LeaderExit::ExitedNonZero(42)
        );
        assert_eq!(
            LeaderExit::from_status(std::process::ExitStatus::from_raw(libc::SIGSEGV)),
            LeaderExit::KilledBySignal(libc::SIGSEGV)
        );
    }

    #[test]
    fn coordinator_preserves_first_cause_and_requests_once() {
        let scope = TestScope::new(None);
        let requests = scope.requests.clone();
        let mut coordinator = GracefulTerminationCoordinator::new().unwrap();
        assert!(coordinator
            .begin(
                TerminationCause::InternalTerminateRequest,
                Duration::from_secs(1),
                &scope
            )
            .unwrap()
            .is_some());
        assert!(coordinator
            .begin(
                TerminationCause::WorkerSignal(WorkerTerminationSignal::Sighup),
                Duration::from_secs(2),
                &scope
            )
            .unwrap()
            .is_none());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        coordinator.record_leader_exit(LeaderExit::ExitedNonZero(42));
        coordinator.record_leader_exit(LeaderExit::ExitedZero);
        assert_eq!(
            coordinator.deadline_expired(),
            GracefulTerminationOutcome::DeadlineExpired {
                cause: TerminationCause::InternalTerminateRequest,
                leader_exit: Some(LeaderExit::ExitedNonZero(42))
            }
        );
    }

    #[test]
    fn deadline_is_bounded_and_does_not_become_success() {
        let scope = TestScope::new(None);
        let mut coordinator = GracefulTerminationCoordinator::new().unwrap();
        let _observer = coordinator
            .begin(
                TerminationCause::InternalTerminateRequest,
                Duration::from_millis(1),
                &scope,
            )
            .unwrap()
            .unwrap();
        let mut fd = libc::pollfd {
            fd: coordinator.timer_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut fd, 1, 1000) }, 1);
        assert!(coordinator.consume_deadline().unwrap());
        assert!(matches!(
            coordinator.deadline_expired(),
            GracefulTerminationOutcome::DeadlineExpired { .. }
        ));
        assert_eq!(scope.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn only_candidate_with_reaped_leader_and_empty_proof_can_finalize() {
        let scope = TestScope::new(None);
        let candidate = GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: Some(LeaderExit::ExitedZero),
            observation: BoundaryTerminalObservation::CgroupEventRevalidated,
        };
        assert!(matches!(
            consume_graceful_outcome(candidate, &scope),
            GracefulFinalizationDecision::FinalizeCooperative(proof)
                if proof.leader_exit() == &LeaderExit::ExitedZero
        ));

        let without_reap = GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: None,
            observation: BoundaryTerminalObservation::CgroupEventRevalidated,
        };
        assert!(matches!(
            consume_graceful_outcome(without_reap, &scope),
            GracefulFinalizationDecision::NeedsEscalation {
                leader_exit: None,
                ..
            }
        ));
    }

    #[test]
    fn failed_proof_and_non_candidate_outcomes_retain_nonfinal_state() {
        let populated = TestScope::new(Some(
            crate::payload_scope::PayloadScopeError::BoundaryNotEmpty,
        ));
        let candidate = GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: Some(LeaderExit::ExitedZero),
            observation: BoundaryTerminalObservation::CgroupEventRevalidated,
        };
        assert!(matches!(
            consume_graceful_outcome(candidate, &populated),
            GracefulFinalizationDecision::NeedsEscalation { .. }
        ));

        let replaced = TestScope::new(Some(crate::payload_scope::PayloadScopeError::UnitReplaced));
        let candidate = GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: Some(LeaderExit::ExitedZero),
            observation: BoundaryTerminalObservation::CgroupEventRevalidated,
        };
        assert!(matches!(
            consume_graceful_outcome(candidate, &replaced),
            GracefulFinalizationDecision::RecoveryRequired { .. }
        ));

        let deadline = GracefulTerminationOutcome::DeadlineExpired {
            cause: TerminationCause::InternalTerminateRequest,
            leader_exit: Some(LeaderExit::ExitedZero),
        };
        assert!(matches!(
            consume_graceful_outcome(deadline, &populated),
            GracefulFinalizationDecision::NeedsEscalation { .. }
        ));
    }

    #[test]
    fn unit_replacement_is_recovery_required() {
        let scope = TestScope::new(Some(crate::payload_scope::PayloadScopeError::UnitReplaced));
        let mut coordinator = GracefulTerminationCoordinator::new().unwrap();
        assert!(matches!(
            coordinator.begin(
                TerminationCause::InternalTerminateRequest,
                Duration::from_secs(1),
                &scope
            ),
            Err(GracefulTerminationOutcome::RecoveryRequired {
                reason: RecoveryReason::BoundaryIdentityChanged,
                ..
            })
        ));
        assert_eq!(scope.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn real_process_signals_are_consumed_by_signalfd() {
        for (raw, expected) in [
            (libc::SIGTERM, WorkerTerminationSignal::Sigterm),
            (libc::SIGINT, WorkerTerminationSignal::Sigint),
            (libc::SIGHUP, WorkerTerminationSignal::Sighup),
        ] {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let signals = WorkerSignalFd::install().unwrap();
                unsafe { libc::kill(libc::getpid(), raw) };
                let mut fd = libc::pollfd {
                    fd: signals.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ok = unsafe { libc::poll(&mut fd, 1, 1000) } == 1
                    && signals
                        .read_signal()
                        .unwrap()
                        .and_then(WorkerTerminationSignal::from_raw)
                        == Some(expected);
                std::mem::forget(signals);
                unsafe { libc::_exit(if ok { 0 } else { 1 }) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
}
