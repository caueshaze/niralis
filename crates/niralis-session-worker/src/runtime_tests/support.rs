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

impl LogindSessionResolver for StubLogind {
    fn resolve_by_pid(&self, _pid: u32) -> Result<Option<LogindSessionIdentity>, LogindError> {
        // The worker first queries membership before PAM. The fixture models
        // a system-manager worker there, then the new session after PAM.
        if self.resolve_by_pid_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return Ok(None);
        }
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
    fn run_child_until_ready(
        &self,
        expectation: SessionChildExpectation,
    ) -> Result<Box<dyn crate::session_child::PendingExecHandoff>, SessionChildError> {
        self.state.child_calls.fetch_add(1, Ordering::SeqCst);
        self.state
            .child_drop_observations
            .fetch_add(self.state.drops.load(Ordering::SeqCst), Ordering::SeqCst);
        self.result.clone()?;
        Ok(Box::new(StubPendingExecHandoff {
            report: SessionChildReport {
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
                    session_class: expectation.runtime.session_class.clone(),
                    session_desktop: expectation.runtime.session_desktop.clone(),
                    session_id: expectation.runtime.session_id.clone(),
                    runtime_dir: expectation.runtime.runtime_dir.clone(),
                    seat: expectation.runtime.seat.clone(),
                    vtnr: expectation.runtime.vtnr,
                    dbus_session_bus_address: expectation.runtime.dbus_session_bus_address.clone(),
                    imported_locale: expectation.runtime.imported_locale.clone(),
                    forbidden_variables_present: Vec::new(),
                    user_bus_connected: true,
                    cwd: expectation.runtime.home.clone(),
                    exec_plan: expectation.runtime.exec_plan.clone(),
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
            },
        }))
    }
}

struct StubPendingExecHandoff {
    report: SessionChildReport,
}

pub(super) struct StubPayloadScopeManager;

struct StubAuthoritativePayloadScope {
    identity: niralis_session::PayloadScopeIdentity,
}

impl crate::payload_scope::AuthoritativePayloadScope for StubAuthoritativePayloadScope {
    fn identity(&self) -> &niralis_session::PayloadScopeIdentity {
        &self.identity
    }
    fn control_group(&self) -> &str {
        "/user.slice/user-1000.slice/niralis-payload-test.scope"
    }
    fn cleanup(
        self: Box<Self>,
        _deadline: std::time::Instant,
    ) -> Result<(), crate::payload_scope::PayloadScopeError> {
        Ok(())
    }
}

impl crate::payload_scope::PayloadScopeManager for StubPayloadScopeManager {
    fn requires_supervisor_registration(&self) -> bool {
        false
    }
    fn prepare(
        &self,
        _report: &SessionChildReport,
        _pidfd: std::os::fd::RawFd,
        expected_uid: u32,
        logind_session_id: &niralis_session::LogindSessionId,
        _worker_pid: u32,
        _launcher_pid: u32,
        _deadline: std::time::Instant,
    ) -> Result<
        Box<dyn crate::payload_scope::AuthoritativePayloadScope>,
        crate::payload_scope::PayloadScopeError,
    > {
        Ok(Box::new(StubAuthoritativePayloadScope {
            identity: niralis_session::PayloadScopeIdentity {
                unit_name: "niralis-payload-0123456789abcdef.scope".into(),
                invocation_id: "0123456789abcdef0123456789abcdef".into(),
                expected_uid,
                logind_session_id: logind_session_id.clone(),
            },
        }))
    }
}

impl crate::session_child::PendingExecHandoff for StubPendingExecHandoff {
    fn report(&self) -> &SessionChildReport {
        &self.report
    }
    fn authoritative_pidfd(&self) -> std::os::fd::RawFd {
        0
    }
    fn commit_exec(self: Box<Self>) -> Result<SessionChildReport, SessionChildError> {
        Ok(self.report.clone())
    }
    fn abort(self: Box<Self>) -> Result<(), SessionChildError> {
        Ok(())
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
            launcher_pid: 0,
            launch_plan: niralis_session::SessionExecPlan {
                source_path: b"/source.desktop".to_vec(),
                executable: b"/bin/true".to_vec(),
                argv: vec![b"true".to_vec()],
            },
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
