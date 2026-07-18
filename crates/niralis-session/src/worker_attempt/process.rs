use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tracing::info;

use crate::{
    worker_io::{read_envelope, write_envelope},
    SessionError, WorkerEnvelope, WorkerRequest, WorkerResponse,
};

pub(crate) struct WorkerAttempt {
    child: Arc<Mutex<Child>>,
    retained_by_supervisor: bool,
    supervisor_channel: Option<UnixStream>,
    writer: Option<JoinHandle<()>>,
    writer_rx: Receiver<Result<(), SessionError>>,
    reader: Option<JoinHandle<()>>,
    reader_rx: Receiver<Result<WorkerEnvelope<WorkerResponse>, SessionError>>,
}

impl WorkerAttempt {
    pub(crate) fn child_id(&self) -> u32 {
        self.child.lock().expect("worker child lock").id()
    }
    pub(crate) fn is_alive(&mut self) -> Result<bool, SessionError> {
        Ok(self
            .child
            .lock()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .try_wait()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .is_none())
    }

    pub(crate) fn shared_child(&self) -> Arc<Mutex<Child>> {
        Arc::clone(&self.child)
    }
    pub(crate) fn retain_by_supervisor(&mut self) {
        self.retained_by_supervisor = true;
    }
    pub(crate) fn supervisor_channel_mut(&mut self) -> &mut UnixStream {
        self.supervisor_channel
            .as_mut()
            .expect("worker supervisor channel exists")
    }
    pub(crate) fn take_supervisor_channel(&mut self) -> UnixStream {
        self.supervisor_channel
            .take()
            .expect("worker supervisor channel ownership exists")
    }
    pub(crate) fn spawn(
        worker_path: &Path,
        worker_environment: &[(String, String)],
        request: WorkerRequest,
    ) -> Result<Self, SessionError> {
        let (mut child, supervisor_channel) = spawn_worker(worker_path, worker_environment)?;
        let stdin = child.stdin.take().ok_or(SessionError::WorkerIoFailed)?;
        let stdout = child.stdout.take().ok_or(SessionError::WorkerIoFailed)?;
        let (writer, writer_rx) = spawn_writer(stdin, request);
        let (reader, reader_rx) = spawn_reader(stdout);

        Ok(Self {
            child: Arc::new(Mutex::new(child)),
            retained_by_supervisor: false,
            supervisor_channel: Some(supervisor_channel),
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
            &self.child,
        )
    }

    pub(crate) fn wait_reader(
        &mut self,
        deadline: Instant,
    ) -> Result<WorkerEnvelope<WorkerResponse>, SessionError> {
        wait_thread_result(
            &self.reader_rx,
            deadline,
            &self.child,
        )
    }

    pub(crate) fn wait_child(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<ExitStatus>, SessionError> {
        wait_for_exit(&self.child, deadline).map(Some)
    }

    pub(crate) fn kill_and_reap(&mut self) {
        kill_and_reap(&self.child);
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
        if !self.retained_by_supervisor {
            self.kill_and_reap();
        }
        self.finish();
    }
}

fn spawn_worker(
    worker_path: &Path,
    worker_environment: &[(String, String)],
) -> Result<(Child, UnixStream), SessionError> {
    const CHILD_SUPERVISOR_FD: libc::c_int = 3;
    let (parent_channel, child_channel) =
        UnixStream::pair().map_err(|_| SessionError::WorkerSpawnFailed)?;
    let child_channel_fd = child_channel.as_raw_fd();
    let mut command = Command::new(worker_path);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .env_clear()
        .envs(worker_environment.iter().cloned())
        .env(
            crate::WORKER_SUPERVISOR_FD_ENV,
            CHILD_SUPERVISOR_FD.to_string(),
        )
        .current_dir("/");
    unsafe {
        command.pre_exec(move || {
            if child_channel_fd != CHILD_SUPERVISOR_FD
                && libc::dup2(child_channel_fd, CHILD_SUPERVISOR_FD) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(CHILD_SUPERVISOR_FD, libc::F_GETFD);
            if flags < 0
                || libc::fcntl(
                    CHILD_SUPERVISOR_FD,
                    libc::F_SETFD,
                    flags & !libc::FD_CLOEXEC,
                ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let result = command.spawn();
    drop(child_channel);

    match result {
        Ok(child) => {
            info!(path = %worker_path.display(), "spawned session worker");
            Ok((child, parent_channel))
        }
        Err(error) => {
            tracing::error!(
                path = %worker_path.display(),
                errno = ?error.raw_os_error(),
                kind = ?error.kind(),
                error = %error,
                "failed to spawn session worker"
            );

            Err(SessionError::WorkerSpawnFailed)
        }
    }
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
