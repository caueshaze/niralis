use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tracing::info;

use crate::{
    worker_io::{read_envelope, write_envelope},
    SessionError, WorkerEnvelope, WorkerRequest, WorkerResponse,
};

pub(crate) struct WorkerAttempt {
    child: Option<Child>,
    writer: Option<JoinHandle<()>>,
    writer_rx: Receiver<Result<(), SessionError>>,
    reader: Option<JoinHandle<()>>,
    reader_rx: Receiver<Result<WorkerEnvelope<WorkerResponse>, SessionError>>,
}

impl WorkerAttempt {
    pub(crate) fn is_alive(&mut self) -> Result<bool, SessionError> {
        Ok(self
            .child
            .as_mut()
            .expect("worker child exists")
            .try_wait()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .is_none())
    }

    pub(crate) fn take_child(&mut self) -> Child {
        self.child.take().expect("worker child ownership exists")
    }
    pub(crate) fn spawn(worker_path: &Path, request: WorkerRequest) -> Result<Self, SessionError> {
        let mut child = spawn_worker(worker_path)?;
        let stdin = child.stdin.take().ok_or(SessionError::WorkerIoFailed)?;
        let stdout = child.stdout.take().ok_or(SessionError::WorkerIoFailed)?;
        let (writer, writer_rx) = spawn_writer(stdin, request);
        let (reader, reader_rx) = spawn_reader(stdout);

        Ok(Self {
            child: Some(child),
            writer: Some(writer),
            writer_rx,
            reader: Some(reader),
            reader_rx,
        })
    }

    pub(crate) fn wait_writer(&mut self, deadline: Instant) -> Result<(), SessionError> {
        wait_thread_result(
            &self.writer_rx,
            deadline,
            self.child.as_mut().expect("worker child exists"),
        )
    }

    pub(crate) fn wait_reader(
        &mut self,
        deadline: Instant,
    ) -> Result<WorkerEnvelope<WorkerResponse>, SessionError> {
        wait_thread_result(
            &self.reader_rx,
            deadline,
            self.child.as_mut().expect("worker child exists"),
        )
    }

    pub(crate) fn wait_child(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<ExitStatus>, SessionError> {
        wait_for_exit(self.child.as_mut().expect("worker child exists"), deadline).map(Some)
    }

    pub(crate) fn kill_and_reap(&mut self) {
        if let Some(child) = self.child.as_mut() {
            kill_and_reap(child);
        }
    }

    pub(crate) fn finish(&mut self) {
        if let Some(handle) = self.writer.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for WorkerAttempt {
    fn drop(&mut self) {
        self.kill_and_reap();
        self.finish();
    }
}

fn spawn_worker(worker_path: &Path) -> Result<Child, SessionError> {
    let child = Command::new(worker_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .env_clear()
        .current_dir("/")
        .spawn()
        .map_err(|_| SessionError::WorkerSpawnFailed)?;
    info!(path = %worker_path.display(), "spawned session worker");
    Ok(child)
}

fn spawn_writer(
    stdin: ChildStdin,
    request: WorkerRequest,
) -> (JoinHandle<()>, Receiver<Result<(), SessionError>>) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut stdin = stdin;
        let _ = sender.send(write_envelope(&mut stdin, request));
    });
    (handle, receiver)
}

fn spawn_reader(
    stdout: ChildStdout,
) -> (
    JoinHandle<()>,
    Receiver<Result<WorkerEnvelope<WorkerResponse>, SessionError>>,
) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut stdout = stdout;
        let _ = sender.send(read_envelope::<WorkerResponse, _>(&mut stdout));
    });
    (handle, receiver)
}

fn wait_thread_result<T>(
    receiver: &Receiver<Result<T, SessionError>>,
    deadline: Instant,
    child: &mut Child,
) -> Result<T, SessionError> {
    let timeout = match deadline.checked_duration_since(Instant::now()) {
        Some(timeout) => timeout,
        None => {
            kill_and_reap(child);
            return Err(SessionError::WorkerTimedOut);
        }
    };

    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            kill_and_reap(child);
            Err(SessionError::WorkerTimedOut)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = reap_child(child);
            Err(SessionError::WorkerIoFailed)
        }
    }
}

fn wait_for_exit(child: &mut Child, deadline: Instant) -> Result<ExitStatus, SessionError> {
    loop {
        if let Some(status) = child.try_wait().map_err(|_| SessionError::WorkerIoFailed)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            kill_and_reap(child);
            return Err(SessionError::WorkerTimedOut);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn kill_and_reap(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) | Err(_) => {}
    }

    let _ = child.kill();
    let _ = reap_child(child);
}

fn reap_child(child: &mut Child) -> Result<(), SessionError> {
    child
        .wait()
        .map(|_| ())
        .map_err(|_| SessionError::WorkerIoFailed)
}
