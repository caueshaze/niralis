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
use crate::{LogindError, LogindSessionId, LogindSessionIdentity, LogindSessionResolver};
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
pub(super) struct StubLogind;

impl LogindSessionResolver for StubLogind {
    fn resolve_by_pid(&self, _pid: u32) -> Result<Option<LogindSessionIdentity>, LogindError> {
        Ok(Some(LogindSessionIdentity {
            id: LogindSessionId::new("test-logind".to_owned()).unwrap(),
            uid: 1000,
            session_type: "wayland".to_owned(),
            class: "user".to_owned(),
            desktop: Some("niri".to_owned()),
            seat: Some("seat0".to_owned()),
            vtnr: Some(1),
        }))
    }
    fn resolve_by_id(
        &self,
        id: &LogindSessionId,
    ) -> Result<Option<LogindSessionIdentity>, LogindError> {
        self.resolve_by_pid(0).map(|identity| {
            identity.map(|mut value| {
                value.id = id.clone();
                value
            })
        })
    }
}

impl SessionChildRunnerFactory for StubChildFactory {
    fn build(
        &self,
        _path: &std::path::Path,
    ) -> Result<Box<dyn SessionChildRunner>, SessionChildError> {
        Ok(Box::new(StubChildRunner {
            state: self.state.clone(),
            result: self.result.clone(),
        }))
    }
}

struct StubChildRunner {
    state: TrackingState,
    result: Result<(), SessionChildError>,
}

impl SessionChildRunner for StubChildRunner {
    fn run_child(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<SessionChildReport, SessionChildError> {
        self.state.child_calls.fetch_add(1, Ordering::SeqCst);
        self.state
            .child_drop_observations
            .fetch_add(self.state.drops.load(Ordering::SeqCst), Ordering::SeqCst);
        self.result.clone()?;
        Ok(SessionChildReport {
            canonical_username: expectation.canonical_username.clone(),
            session_id: expectation.session_id,
            child_pid: 1,
            applied_credentials: AppliedCredentials {
                uid: expectation.target_credentials.uid,
                gid: expectation.target_credentials.gid,
                supplementary_gids: expectation.target_credentials.supplementary_gids.clone(),
            },
            credential_proof: crate::session_child::SessionChildCredentialProof {
                real_uid: expectation.target_credentials.uid,
                effective_uid: expectation.target_credentials.uid,
                saved_uid: expectation.target_credentials.uid,
                real_gid: expectation.target_credentials.gid,
                effective_gid: expectation.target_credentials.gid,
                saved_gid: expectation.target_credentials.gid,
                supplementary_gids: expectation.target_credentials.supplementary_gids.clone(),
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
                pid: 1,
                sid: 1,
                pgid: 1,
            },
            runtime_environment: crate::session_child::RuntimeEnvironmentProof {
                home: expectation.runtime.home.clone(),
                user: expectation.canonical_username.clone(),
                logname: expectation.canonical_username.clone(),
                shell: expectation.runtime.shell.clone(),
                path: crate::session_child::DEFAULT_SESSION_PATH.into(),
                session_type: expectation.runtime.session_type.clone(),
                cwd: expectation.runtime.home.clone(),
            },
            exec_probe_version: crate::session_child::SESSION_EXEC_PROBE_VERSION,
            terminal_proof: expectation.terminal.as_ref().map(|terminal| {
                crate::session_child::SessionChildTerminalProof {
                    seat: terminal.seat.clone(),
                    vtnr: terminal.vtnr,
                    fd: terminal.fd,
                    device_major: terminal.device_major,
                    device_minor: terminal.device_minor,
                    controlling_sid: 1,
                    foreground_pgid: 1,
                }
            }),
        })
    }
}

impl SupplementaryGroupsResolver for StubGroupsResolver {
    fn resolve(&self, identity: &UnixIdentity) -> Result<Vec<u32>, GroupResolutionError> {
        self.state.groups_calls.fetch_add(1, Ordering::SeqCst);
        *self
            .last_username
            .lock()
            .expect("last_username mutex should lock") = Some(identity.username.clone());
        self.result.clone()
    }
}

impl UnixIdentityResolver for StubIdentityResolver {
    fn resolve(&self, username: &str) -> Result<UnixIdentity, IdentityError> {
        self.state.resolve_calls.fetch_add(1, Ordering::SeqCst);
        *self
            .last_username
            .lock()
            .expect("last_username mutex should lock") = Some(username.to_owned());
        self.result.clone()
    }
}

pub(super) fn request() -> WorkerEnvelope<WorkerRequest> {
    WorkerEnvelope {
        version: niralis_session::WORKER_PROTOCOL_VERSION,
        message: WorkerRequest::PamSession {
            request: SessionRequest {
                username: "login-alias".to_owned(),
                session: SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: SessionKind::Wayland,
                },
            },
            pam_service: "niralis".to_owned(),
            password: WorkerSecret::new("secret".to_owned()),
            session_child_path: "/usr/libexec/niralis-session-child".into(),
            session_probe_path: "/usr/libexec/niralis-session-probe".into(),
            control_path: std::path::PathBuf::new(),
            worker_id: String::new(),
        },
    }
}

pub(super) fn identity() -> UnixIdentity {
    UnixIdentity {
        username: "caue".to_owned(),
        uid: 1000,
        gid: 1000,
        home: "/home/caue".into(),
        shell: "/bin/bash".into(),
    }
}
