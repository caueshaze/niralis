impl DaemonFixture {
    fn spawn(mode: &str) -> Self {
        let directory = tempfile::tempdir().expect("fixture directory");
        let recovery = directory.path().join("recovery");
        let lock = directory.path().join("recovery.lock");
        Self::spawn_with_storage(mode, directory, recovery, lock)
    }

    fn spawn_reusing_storage(mode: &str, recovery: &Path) -> Self {
        let directory = tempfile::tempdir().expect("fixture socket directory");
        let lock = recovery
            .parent()
            .expect("recovery parent")
            .join("recovery.lock");
        Self::spawn_with_storage(mode, directory, recovery.to_path_buf(), lock)
    }

    fn spawn_reusing_storage_with_env(
        mode: &str,
        recovery: &Path,
        environment: &[(&str, &str)],
    ) -> Self {
        let directory = tempfile::tempdir().expect("fixture socket directory");
        let lock = recovery
            .parent()
            .expect("recovery parent")
            .join("recovery.lock");
        Self::spawn_with_storage_and_env(mode, directory, recovery.to_path_buf(), lock, environment)
    }

    fn spawn_with_storage(
        mode: &str,
        directory: TempDir,
        recovery: PathBuf,
        lock: PathBuf,
    ) -> Self {
        Self::spawn_with_storage_and_env(mode, directory, recovery, lock, &[])
    }

    fn spawn_with_storage_and_env(
        mode: &str,
        directory: TempDir,
        recovery: PathBuf,
        lock: PathBuf,
        environment: &[(&str, &str)],
    ) -> Self {
        let report_path = directory.path().join("report.sock");
        let barrier_path = directory.path().join("barrier.sock");
        let report = UnixListener::bind(&report_path).expect("report listener");
        let barrier = UnixListener::bind(&barrier_path).expect("barrier listener");
        let mut command = Command::new(env!("CARGO_BIN_EXE_fixture-supervisor-daemon"));
        command
            .arg(env!("CARGO_BIN_EXE_fixture-supervisor-worker"))
            .arg(&recovery)
            .arg(&lock)
            .arg(mode)
            .arg(&report_path)
            .arg(&barrier_path);
        for (key, value) in environment {
            command.env(key, value);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn fixture daemon");
        let stdin = child.stdin.take().expect("daemon stdin");
        let operation_log = recovery
            .parent()
            .expect("recovery parent")
            .join("operations.log");
        Self {
            child,
            stdin,
            report,
            barrier,
            worker_report: None,
            _directory: directory,
            recovery,
            operation_log,
        }
    }

    fn receive_barrier(&self) -> String {
        let (stream, _) = self.barrier.accept().expect("barrier connection");
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .expect("barrier line");
        line
    }

    fn start(&mut self) {
        writeln!(self.stdin, "start").expect("start command");
        self.stdin.flush().expect("flush start command");
    }

    fn receive_processes(&mut self) -> [u32; 3] {
        let (stream, _) = self.report.accept().expect("process report");
        let mut line = String::new();
        BufReader::new(&stream)
            .read_line(&mut line)
            .expect("process report line");
        let mut values = line
            .split_ascii_whitespace()
            .map(|value| value.parse().expect("process pid"));
        self.worker_report = Some(stream);
        [
            values.next().expect("worker pid"),
            values.next().expect("leader pid"),
            values.next().expect("payload member pid"),
        ]
    }

    fn kill_exact(&mut self) {
        let pid = self.child.id();
        let pidfd = pidfd_open(pid);
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) }, 0);
        wait_pidfd(&pidfd);
        let status = self.child.wait().expect("daemon wait");
        assert!(status.success() || status.signal() == Some(libc::SIGKILL));
    }

    fn events(&self) -> String {
        fs::read_to_string(&self.operation_log).unwrap_or_default()
    }
}

fn record_path(recovery: &Path) -> PathBuf {
    fs::read_dir(recovery)
        .expect("recovery directory")
        .map(|entry| entry.expect("record entry").path())
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .expect("durable record")
}

fn rewrite_record(recovery: &Path, state: &str, payload_intent: bool) -> PathBuf {
    let path = record_path(recovery);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("record bytes")).expect("record JSON");
    value["state"] = serde_json::Value::String(state.to_owned());
    value["sequence"] = serde_json::Value::from(value["sequence"].as_u64().unwrap() + 1);
    if payload_intent {
        value["operation_ledger"]["payload_kill"] = serde_json::json!({
            "IntentPersisted": { "attempt_id": 91 }
        });
    }
    let temporary = recovery.join(".fixture-record.tmp");
    let bytes = serde_json::to_vec(&value).expect("record encoding");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .expect("temporary record");
    file.write_all(&bytes).expect("temporary record write");
    file.sync_all().expect("temporary record sync");
    drop(file);
    fs::rename(&temporary, &path).expect("record replacement");
    let directory = fs::File::open(recovery).expect("recovery directory fd");
    directory.sync_all().expect("recovery directory sync");
    path
}

