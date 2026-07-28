
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
        message: WorkerRequest::PamSession(niralis_session::WorkerPamSessionRequest {
            request: SessionRequest {
                username: "login-alias".to_owned(),
                session: SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: SessionKind::Wayland,
                },
            },
            connection: None,
            pam_service: "niralis".to_owned(),
            password: WorkerSecret::new("secret".to_owned()),
            session_child_path: Box::new("/usr/libexec/niralis-session-child".into()),
            session_probe_path: Box::new("/usr/libexec/niralis-session-probe".into()),
            control_path: Box::new(std::path::PathBuf::new()),
            worker_id: String::new(),
            launcher_pid: 0,
            transaction: Box::new(niralis_session::WorkerTransactionIdentity { transaction_id: String::new(), admission_attempt_id: 1, lifecycle_id: String::new(), seat: "seat0".into(), seat_generation: 1, stage: "reserved".into() }),
            launch_plan: Box::new(niralis_session::SessionExecPlan {
                source_path: b"/source.desktop".to_vec(),
                executable: b"/bin/true".to_vec(),
                argv: vec![b"true".to_vec()],
            }),
        }),
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
