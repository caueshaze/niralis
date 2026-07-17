
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

    fn request_graceful_termination(&self) -> Result<(), crate::payload_scope::PayloadScopeError> {
        Ok(())
    }

    fn boundary_appears_terminal(&self) -> Result<bool, crate::payload_scope::PayloadScopeError> {
        Ok(true)
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
