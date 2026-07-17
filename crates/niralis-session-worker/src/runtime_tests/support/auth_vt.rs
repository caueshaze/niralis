use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use niralis_auth::{
    AuthError, AuthSessionError, AuthenticatedTransaction, AuthenticatedUser, Authenticator,
};
use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{SessionRequest, WorkerEnvelope, WorkerRequest, WorkerSecret};

use crate::identity::{
    GroupResolutionError, IdentityError, SupplementaryGroupsResolver, UnixIdentity,
    UnixIdentityResolver,
};
use crate::isolation::{CapabilityState, PostDropIsolationProof};
use crate::privilege_drop::AppliedCredentials;
use crate::runtime::WorkerAuthenticatorFactory;
use crate::session_child::{
    SessionChildError, SessionChildExpectation, SessionChildReport, SessionChildRunner,
    SessionChildRunnerFactory,
};
use crate::{
    LogindError, LogindSessionId, LogindSessionIdentity, LogindSessionResolver,
    PamSelinuxExecContext, SelinuxContextManager, SelinuxError,
};
use crate::{VirtualTerminalAllocator, VirtualTerminalError, VirtualTerminalLease};
use niralis_auth::{SeatId, VirtualTerminalId};

#[derive(Clone, Default)]
pub(super) struct TrackingState {
    pub(super) authenticate_calls: Arc<AtomicUsize>,
    pub(super) resolve_calls: Arc<AtomicUsize>,
    pub(super) groups_calls: Arc<AtomicUsize>,
    pub(super) open_calls: Arc<AtomicUsize>,
    pub(super) drops: Arc<AtomicUsize>,
    pub(super) child_calls: Arc<AtomicUsize>,
    pub(super) child_drop_observations: Arc<AtomicUsize>,
}

#[derive(Default)]
pub(super) struct StubVtAllocator;

impl VirtualTerminalAllocator for StubVtAllocator {
    fn allocate(
        &self,
        seat: &SeatId,
    ) -> Result<Box<dyn VirtualTerminalLease>, VirtualTerminalError> {
        Ok(Box::new(StubVtLease {
            seat: seat.clone(),
            vtnr: VirtualTerminalId::new(1).unwrap(),
        }))
    }
}

struct StubVtLease {
    seat: SeatId,
    vtnr: VirtualTerminalId,
}

impl VirtualTerminalLease for StubVtLease {
    fn seat(&self) -> &SeatId {
        &self.seat
    }
    fn vtnr(&self) -> VirtualTerminalId {
        self.vtnr
    }
    fn duplicate_terminal_fd(&self) -> Result<OwnedFd, VirtualTerminalError> {
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(VirtualTerminalError::OperationFailed);
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    fn activate(&mut self, _wait: Duration) -> Result<(), VirtualTerminalError> {
        Ok(())
    }
    fn release(&mut self) -> Result<(), VirtualTerminalError> {
        Ok(())
    }
}

pub(super) struct StubFactory {
    pub(super) state: TrackingState,
    pub(super) auth_result: Result<(), AuthError>,
    pub(super) open_ok: bool,
    pub(super) open_panics: bool,
    pub(super) pam_username: &'static str,
}

impl WorkerAuthenticatorFactory for StubFactory {
    fn build(&self, _pam_service: &str) -> Box<dyn Authenticator> {
        Box::new(StubAuthenticator {
            state: self.state.clone(),
            auth_result: self.auth_result.clone(),
            open_ok: self.open_ok,
            open_panics: self.open_panics,
            pam_username: self.pam_username,
        })
    }
}

struct StubAuthenticator {
    state: TrackingState,
    auth_result: Result<(), AuthError>,
    open_ok: bool,
    open_panics: bool,
    pam_username: &'static str,
}

impl Authenticator for StubAuthenticator {
    fn authenticate(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError> {
        self.state.authenticate_calls.fetch_add(1, Ordering::SeqCst);
        match &self.auth_result {
            Ok(()) => Ok(Box::new(StubTransaction {
                user: AuthenticatedUser {
                    username: self.pam_username.to_owned(),
                    display_name: username.to_owned(),
                },
                state: self.state.clone(),
                open_ok: self.open_ok,
                open_panics: self.open_panics,
            })),
            Err(error) => Err(error.clone()),
        }
    }
}

struct StubTransaction {
    user: AuthenticatedUser,
    state: TrackingState,
    open_ok: bool,
    open_panics: bool,
}

impl AuthenticatedTransaction for StubTransaction {
    fn user(&self) -> &AuthenticatedUser {
        &self.user
    }

    fn open_session(
        &mut self,
        _metadata: &niralis_auth::PamSessionMetadata,
    ) -> Result<(), AuthSessionError> {
        self.state.open_calls.fetch_add(1, Ordering::SeqCst);
        if self.open_panics {
            panic!("boom");
        }
        if self.open_ok {
            Ok(())
        } else {
            Err(AuthSessionError::OpenFailed)
        }
    }

    fn session_environment(
        &mut self,
    ) -> Result<niralis_auth::PamSessionEnvironment, AuthSessionError> {
        Ok(niralis_auth::PamSessionEnvironment {
            session_id: "test-logind".to_owned(),
            runtime_dir: niralis_auth::PamUnixPath::new(b"/tmp/niralis-runtime".to_vec())?,
            imported_locale: Vec::new(),
        })
    }
}

impl Drop for StubTransaction {
    fn drop(&mut self) {
        self.state.drops.fetch_add(1, Ordering::SeqCst);
    }
}

pub(super) struct StubIdentityResolver {
    pub(super) state: TrackingState,
    pub(super) result: Result<UnixIdentity, IdentityError>,
    pub(super) last_username: Arc<Mutex<Option<String>>>,
}

pub(super) struct StubGroupsResolver {
    pub(super) state: TrackingState,
    pub(super) result: Result<Vec<u32>, GroupResolutionError>,
    pub(super) last_username: Arc<Mutex<Option<String>>>,
}

pub(super) struct StubChildFactory {
    pub(super) state: TrackingState,
    pub(super) result: Result<(), SessionChildError>,
}

#[derive(Default)]
pub(super) struct StubLogind {
    resolve_by_pid_calls: AtomicUsize,
}

#[derive(Default)]
pub(super) struct StubSelinux;

impl SelinuxContextManager for StubSelinux {
    fn capture_pending(&self) -> Result<Option<PamSelinuxExecContext>, SelinuxError> {
        Ok(None)
    }
    fn clear_pending(&self) -> Result<(), SelinuxError> {
        Ok(())
    }
    fn apply_pending(&self, _context: &PamSelinuxExecContext) -> Result<(), SelinuxError> {
        Ok(())
    }
    fn context_for_pid(&self, _pid: u32) -> Result<PamSelinuxExecContext, SelinuxError> {
        Err(SelinuxError::QueryFailed)
    }
}
