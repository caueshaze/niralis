impl FullWorker {
    fn spawn(mode: &str) -> Self {
        let mut worker = Self::spawn_process(mode, false);
        worker.expect("ScopePrepared");
        worker.expect("PinAcquired");
        worker.expect("CommitExecCalled:count=1");
        worker.expect("Running");
        worker.expect("TimerFdCloexec");
        worker.assert_started_frame();
        worker
    }

    fn spawn_barrier(mode: &str) -> Self {
        Self::spawn_process(mode, true)
    }

    fn spawn_process(mode: &str, with_control: bool) -> Self {
        let (parent_harness, child_harness) = UnixStream::pair().expect("harness socketpair");
        let (parent_supervisor, child_supervisor) =
            UnixStream::pair().expect("supervisor socketpair");
        parent_harness
            .set_read_timeout(Some(HARNESS_TIMEOUT))
            .expect("bounded harness timeout");
        parent_harness
            .set_write_timeout(Some(HARNESS_TIMEOUT))
            .expect("bounded harness write timeout");
        let inherited_harness = duplicate_inherited_fd(child_harness.as_raw_fd());
        let inherited_supervisor = duplicate_inherited_fd(child_supervisor.as_raw_fd());
        drop(child_harness);
        drop(child_supervisor);
        let harness_fd = inherited_harness.as_raw_fd();
        let supervisor_fd = inherited_supervisor.as_raw_fd();
        let mut command = Command::new(env!("CARGO_BIN_EXE_fixture-full-worker"));
        command
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("NIRALIS_FULL_WORKER_HARNESS_FD", "3")
            .env(niralis_session::WORKER_SUPERVISOR_FD_ENV, "4");
        unsafe {
            command.pre_exec(move || {
                if harness_fd != 3 && libc::dup2(harness_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let flags = libc::fcntl(3, libc::F_GETFD);
                if flags < 0 || libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(supervisor_fd, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let flags = libc::fcntl(4, libc::F_GETFD);
                if flags < 0 || libc::fcntl(4, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let control_dir = with_control.then(|| tempfile::tempdir().expect("control tempdir"));
        let control_path = control_dir
            .as_ref()
            .map_or_else(std::path::PathBuf::new, |dir| {
                dir.path().join("worker.sock")
            });
        let mut child = command.spawn().expect("spawn full worker fixture");
        drop(inherited_harness);
        drop(inherited_supervisor);
        let stdin = child.stdin.take().expect("worker protocol stdin");
        let stdout = BufReader::new(child.stdout.take().expect("worker protocol stdout"));
        let mut worker = Self {
            child,
            supervisor: Some(parent_supervisor),
            stdout,
            harness: BufReader::new(parent_harness),
            events: Vec::new(),
            leader_pid: None,
            member_pid: None,
            _control_dir: control_dir,
            control_path,
        };
        worker.expect("BootstrapEntered");
        worker.expect("SignalMaskInstalled");
        worker.expect("SignalFdCloexec");
        worker.expect("SupervisorFdCloexec");
        worker.send_request(stdin);
        worker.expect("RequestAccepted");
        worker.expect("VtAcquired");
        worker.expect("PamOpened");
        worker.expect("PayloadSignalMaskRestored");
        worker.expect("PayloadFdHygieneVerified");
        worker.expect_prefix("LeaderPid:");
        if mode == "leader-exit-remaining-member" {
            worker.expect_prefix("BoundaryMemberPid:");
        }
        worker.expect("PendingExecHandoffReady");
        worker
    }

    fn send_request(&mut self, mut stdin: ChildStdin) {
        let request = WorkerEnvelope {
            version: niralis_session::WORKER_PROTOCOL_VERSION,
            message: WorkerRequest::PamSession {
                request: SessionRequest {
                    username: "fixture-user".into(),
                    session: SessionInfo {
                        id: "niri".into(),
                        name: "Niri".into(),
                        kind: SessionKind::Wayland,
                    },
                },
                launch_plan: SessionExecPlan {
                    source_path: b"/fixture.desktop".to_vec(),
                    executable: b"/bin/true".to_vec(),
                    argv: vec![b"true".to_vec()],
                },
                pam_service: "niralis-fixture".into(),
                password: WorkerSecret::new("fixture-secret".into()),
                session_child_path: "/fixture/session-child".into(),
                session_probe_path: "/fixture/session-probe".into(),
                control_path: self.control_path.clone(),
                worker_id: "fixture-worker".into(),
                launcher_pid: std::process::id(),
            },
        };
        serde_json::to_writer(&mut stdin, &request).expect("serialize worker request");
        stdin.write_all(b"\n").expect("frame worker request");
        stdin.flush().expect("flush worker request");
        drop(stdin);
    }

    fn assert_started_frame(&mut self) {
        let envelope = self.read_response();
        assert_eq!(envelope.version, niralis_session::WORKER_PROTOCOL_VERSION);
        assert!(matches!(envelope.message, WorkerResponse::Started { .. }));
    }

    fn read_response(&mut self) -> WorkerEnvelope<WorkerResponse> {
        if self.stdout.buffer().is_empty() {
            let mut pollfd = libc::pollfd {
                fd: self.stdout.get_ref().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe {
                    libc::poll(
                        &mut pollfd,
                        1,
                        i32::try_from(HARNESS_TIMEOUT.as_millis()).unwrap(),
                    )
                },
                1,
                "production protocol response timed out; events={:?}",
                self.events
            );
        }
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .expect("read production worker response");
        assert!(line.len() <= niralis_session::MAX_WORKER_MESSAGE_BYTES);
        serde_json::from_str(&line).expect("parse production worker response")
    }

    fn expect_preparing(&mut self) {
        let envelope = self.read_response();
        assert_eq!(envelope.version, niralis_session::WORKER_PROTOCOL_VERSION);
        assert!(matches!(
            envelope.message,
            WorkerResponse::Preparing { ref worker_id } if worker_id == "fixture-worker"
        ));
    }

    fn expect_prepared(&mut self) -> (String, PayloadScopeIdentity) {
        let envelope = self.read_response();
        match envelope.message {
            WorkerResponse::PayloadScopePrepared {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                scope_identity,
                ..
            } => {
                assert_eq!(worker_id, "fixture-worker");
                assert_eq!(expected_worker_pid, self.child.id());
                assert_eq!(registration_nonce, scope_identity.invocation_id);
                (registration_nonce, scope_identity)
            }
            response => panic!("expected PayloadScopePrepared, got {response:?}"),
        }
    }

    fn acknowledge_scope(&mut self, registration_nonce: &str) {
        let stream = self
            .supervisor
            .as_mut()
            .expect("dedicated supervisor channel remains connected");
        niralis_session::write_control_request(
            stream,
            WorkerControlRequest::PayloadScopeRegistered {
                worker_id: "fixture-worker".into(),
                expected_worker_pid: self.child.id(),
                registration_nonce: registration_nonce.to_owned(),
            },
        )
        .expect("send authenticated scope acknowledgement");
    }

}
