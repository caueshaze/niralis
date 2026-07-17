
impl FixtureState {
    fn new(mode: FixtureMode) -> Result<Self, niralis_session::SessionError> {
        let boundary = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if boundary < 0 {
            return Err(niralis_session::SessionError::WorkerIoFailed);
        }
        Ok(Self {
            mode,
            pid: Mutex::new(None),
            member_pid: Mutex::new(None),
            pidfd: Mutex::new(None),
            command: Mutex::new(None),
            boundary: unsafe { OwnedFd::from_raw_fd(boundary) },
            terminal: AtomicBool::new(false),
            reaped: AtomicBool::new(false),
            kill_count: AtomicUsize::new(0),
            forced_kill_count: AtomicUsize::new(0),
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
