
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
