use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};

use tempfile::TempDir;

struct DaemonFixture {
    child: Child,
    stdin: ChildStdin,
    report: UnixListener,
    barrier: UnixListener,
    worker_report: Option<UnixStream>,
    _directory: TempDir,
    recovery: PathBuf,
    operation_log: PathBuf,
}

struct PrivateBusFixture {
    bus: Child,
    owner_children: Vec<Child>,
    _directory: TempDir,
    address: String,
}

impl Drop for PrivateBusFixture {
    fn drop(&mut self) {
        for child in &mut self.owner_children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = self.bus.kill();
        let _ = self.bus.wait();
    }
}

impl PrivateBusFixture {
    fn start() -> Self {
        let directory = tempfile::tempdir().expect("private bus directory");
        let mut bus = Command::new("dbus-daemon")
            .args([
                "--session",
                "--nofork",
                "--print-address=1",
                "--print-pid=1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("private dbus-daemon");
        let stdout = bus.stdout.take().expect("dbus stdout");
        let mut output = BufReader::new(stdout);
        let mut address = String::new();
        output.read_line(&mut address).expect("dbus address");
        assert!(!address.trim().is_empty(), "dbus address missing");
        // dbus-daemon writes address and pid on the same inherited stdout
        // pipe.  Dropping the reader after only the first line can race its
        // second write and SIGPIPE the private bus before any fixture joins.
        let mut pid_line = String::new();
        output.read_line(&mut pid_line).expect("dbus pid");
        let pid = pid_line.trim().parse::<u32>().expect("numeric dbus pid");
        assert_eq!(bus.id(), pid, "dbus pid does not match child");
        Self {
            bus,
            owner_children: Vec::new(),
            _directory: directory,
            address: address.trim().to_owned(),
        }
    }

    fn start_owner(&mut self, name: &str) -> u32 {
        let ready_path = self
            ._directory
            .path()
            .join(format!("{}.ready", self.owner_children.len()));
        let listener = UnixListener::bind(&ready_path).expect("owner ready socket");
        let child = Command::new(env!("CARGO_BIN_EXE_fixture-dbus-owner"))
            .arg(&self.address)
            .arg(name)
            .arg(&ready_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("dbus owner service");
        let pid = child.id();
        self.owner_children.push(child);
        let (ready, _) = listener.accept().expect("owner ready");
        let mut line = String::new();
        BufReader::new(ready)
            .read_line(&mut line)
            .expect("owner ready line");
        assert!(line.starts_with("ready"), "owner={name} ready={line:?}");
        pid
    }

    fn start_systemd_payload(
        &mut self,
        record: &serde_json::Value,
        member_pid: u32,
        operation_log: &Path,
    ) {
        let ready_path = self
            ._directory
            .path()
            .join(format!("systemd-{}.ready", self.owner_children.len()));
        let listener = UnixListener::bind(&ready_path).expect("systemd ready socket");
        let leader_pid = record["leader_pid"].as_u64().expect("leader pid") as u32;
        let leader_starttime = record["leader_starttime"]
            .as_u64()
            .expect("leader starttime");
        let member_starttime = proc_starttime(member_pid).expect("member starttime");
        let child = Command::new(env!("CARGO_BIN_EXE_fixture-dbus-systemd"))
            .arg(&self.address)
            .arg(record["payload_unit"].as_str().expect("unit"))
            .arg(record["invocation_id"].as_str().expect("invocation"))
            .arg(record["object_path"].as_str().expect("object path"))
            .arg(record["control_group"].as_str().expect("control group"))
            .arg(leader_pid.to_string())
            .arg(leader_starttime.to_string())
            .arg(member_pid.to_string())
            .arg(member_starttime.to_string())
            .arg(&ready_path)
            .arg(operation_log)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("systemd payload service");
        self.owner_children.push(child);
        let (ready, _) = listener.accept().expect("systemd ready");
        let mut line = String::new();
        BufReader::new(ready)
            .read_line(&mut line)
            .expect("systemd ready line");
        assert!(line.starts_with("ready"), "systemd={line:?}");
    }

    fn start_logind_session(&mut self, record: &serde_json::Value, operation_log: &Path) -> u32 {
        let ready_path = self
            ._directory
            .path()
            .join(format!("logind-{}.ready", self.owner_children.len()));
        let listener = UnixListener::bind(&ready_path).expect("logind ready socket");
        let child = Command::new(env!("CARGO_BIN_EXE_fixture-dbus-logind"))
            .arg(&self.address)
            .arg(record["logind_session_id"].as_str().expect("session id"))
            .arg(record["logind_object_path"].as_str().expect("session path"))
            .arg(record["uid"].as_u64().expect("uid").to_string())
            .arg(record["username"].as_str().expect("username"))
            .arg(
                record["worker_pid"]
                    .as_u64()
                    .expect("worker pid")
                    .to_string(),
            )
            .arg(record["seat"].as_str().expect("seat"))
            .arg(record["target_vt"].as_u64().expect("target vt").to_string())
            .arg(record["session_name"].as_str().expect("desktop"))
            .arg(&ready_path)
            .arg(operation_log)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("logind session service");
        let pid = child.id();
        self.owner_children.push(child);
        let (ready, _) = listener.accept().expect("logind ready");
        let mut line = String::new();
        BufReader::new(ready)
            .read_line(&mut line)
            .expect("logind ready line");
        assert!(line.starts_with("ready"), "logind={line:?}");
        pid
    }
}

impl Drop for DaemonFixture {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGKILL) };
            let _ = self.child.wait();
        }
    }
}

