
struct SessionChildAttempt {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    reader: Option<JoinHandle<()>>,
    response_rx: Receiver<Result<Vec<u8>, SessionChildError>>,
    status_read: Option<OwnedFd>,
}

impl SessionChildAttempt {
    fn take_child(&mut self) -> Child {
        self.child.take().expect("child exists")
    }
}

impl SessionChildAttempt {
    fn spawn(
        path: &Path,
        payload: Vec<u8>,
        terminal_fd: Option<OwnedFd>,
    ) -> Result<Self, SessionChildError> {
        let mut command = Command::new(path);
        let (status_read, status_write) = make_status_pipe()?;
        let status_raw = status_write.as_raw_fd();
        let terminal_source_fd = terminal_fd.as_ref().map(AsRawFd::as_raw_fd);
        let fd_mapping_collision = terminal_source_fd == Some(4) || status_raw == 3;
        tracing::debug!(
            status_source_fd = status_raw,
            status_target_fd = 4,
            terminal_source_fd = ?terminal_source_fd,
            terminal_target_fd = 3,
            fd_mapping_collision,
            "prepared session child fd mapping"
        );
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(move || {
                if libc::dup2(status_raw, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let terminal_fd_keepalive = terminal_fd;
        if let Some(terminal_fd) = terminal_fd_keepalive.as_ref() {
            let source_fd = std::os::fd::AsRawFd::as_raw_fd(terminal_fd);
            unsafe {
                use std::os::unix::process::CommandExt;
                command.pre_exec(move || {
                    if libc::dup2(source_fd, 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env_clear()
            .current_dir("/")
            .spawn()
            .map_err(|error| {
                warn!(
                    path = %path.display(),
                    errno = ?error.raw_os_error(),
                    kind = ?error.kind(),
                    error = %error,
                    status_source_fd = status_raw,
                    terminal_source_fd = ?terminal_source_fd,
                    fd_mapping_collision,
                    "failed to spawn session child"
                );
                SessionChildError::SpawnFailed
            })?;
        let mut child = child;
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                warn!("session child did not provide stdin for the private request");
                kill_and_reap(&mut child);
                return Err(SessionChildError::IoFailed);
            }
        };
        let mut stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                warn!("session child did not provide stdout for the private response");
                kill_and_reap(&mut child);
                return Err(SessionChildError::IoFailed);
            }
        };
        let mut stdin = stdin;
        stdin
            .write_all(&payload)
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|error| {
                warn!(
                    errno = ?error.raw_os_error(),
                    error = %error,
                    request_bytes = payload.len(),
                    "writing the private session-child request failed"
                );
                SessionChildError::IoFailed
            })?;
        let (response_tx, response_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let _ = response_tx.send(read_child_response(&mut stdout));
        });
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            reader: Some(reader),
            response_rx,
            status_read: Some(status_read),
        })
    }

    fn wait_reader(&self, deadline: Instant) -> Result<Vec<u8>, SessionChildError> {
        wait_result(&self.response_rx, deadline)
    }

    fn send_commit(&mut self, _deadline: Instant) -> Result<(), SessionChildError> {
        let mut stdin = self.stdin.take().ok_or(SessionChildError::IoFailed)?;
        let message = SessionChildEnvelope {
            version: SESSION_CHILD_PROTOCOL_VERSION,
            message: SessionChildCommit::Exec,
        };
        serde_json::to_writer(&mut stdin, &message).map_err(|error| {
            warn!(error = %error, "serializing CommitExec for the session child failed");
            SessionChildError::IoFailed
        })?;
        stdin
            .write_all(b"\n")
            .map_err(|error| {
                warn!(errno = ?error.raw_os_error(), error = %error, "writing CommitExec to the session child failed");
                SessionChildError::IoFailed
            })?;
        stdin.flush().map_err(|error| {
            warn!(errno = ?error.raw_os_error(), error = %error, "flushing CommitExec to the session child failed");
            SessionChildError::IoFailed
        })
    }

    fn wait_exec_status(&mut self, deadline: Instant) -> Result<ExecStatus, SessionChildError> {
        let fd = self.status_read.take().ok_or(SessionChildError::IoFailed)?;
        let timeout = remaining(deadline)?;
        read_exec_status(fd, timeout)
    }

    fn kill_and_reap(&mut self) {
        if let Some(child) = self.child.as_mut() {
            kill_and_reap(child);
        }
    }

    fn finish(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn make_status_pipe() -> Result<(OwnedFd, OwnedFd), SessionChildError> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SessionChildError::IoFailed);
    }
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

enum ExecStatus {
    Success,
    Failure(FinalExecFailure),
}
