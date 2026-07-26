use std::os::unix::process::CommandExt;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;

use tracing::info;

struct SpawnedFixtureSupervisorTransport {
    handle: FixtureSupervisorTransportHandle,
    child_read_fd: libc::c_int,
    child_write_fd: libc::c_int,
}

fn spawn_worker(
    worker_path: &Path,
    worker_environment: &[(String, String)],
    fixture_supervisor_transport: bool,
) -> Result<(Child, UnixStream, Option<FixtureSupervisorTransportHandle>), SessionError> {
    const CHILD_SUPERVISOR_FD: libc::c_int = 3;
    let (parent_channel, child_channel) =
        UnixStream::pair().map_err(|_| SessionError::WorkerSpawnFailed)?;
    let child_channel_fd = child_channel.as_raw_fd();
    let fixture_transport = if fixture_supervisor_transport {
        Some(create_fixture_supervisor_transport()?)
    } else {
        None
    };
    let fixture_child_read_fd = fixture_transport.as_ref().map(|transport| transport.child_read_fd);
    let fixture_child_write_fd = fixture_transport.as_ref().map(|transport| transport.child_write_fd);
    let mut command = Command::new(worker_path);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .env_clear()
        .envs(worker_environment.iter().cloned())
        .env(crate::WORKER_SUPERVISOR_FD_ENV, CHILD_SUPERVISOR_FD.to_string())
        .current_dir("/");
    if fixture_transport.is_some() {
        command
            .env(crate::FIXTURE_SUPERVISOR_TRANSPORT_ENV, "pipe")
            .env(
                crate::FIXTURE_SUPERVISOR_READ_FD_ENV,
                fixture_child_read_fd.expect("fixture read fd").to_string(),
            )
            .env(
                crate::FIXTURE_SUPERVISOR_WRITE_FD_ENV,
                fixture_child_write_fd.expect("fixture write fd").to_string(),
            );
    }
    unsafe {
        command.pre_exec(move || {
            if child_channel_fd != CHILD_SUPERVISOR_FD
                && libc::dup2(child_channel_fd, CHILD_SUPERVISOR_FD) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(CHILD_SUPERVISOR_FD, libc::F_GETFD);
            if flags < 0
                || libc::fcntl(CHILD_SUPERVISOR_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if let (Some(read_fd), Some(write_fd)) = (fixture_child_read_fd, fixture_child_write_fd) {
                for fd in [read_fd, write_fd] {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            Ok(())
        });
    }
    let result = command.spawn();
    drop(child_channel);
    match result {
        Ok(child) => {
            info!(path = %worker_path.display(), "spawned session worker");
            Ok((child, parent_channel, fixture_transport.map(|transport| transport.handle)))
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

fn create_fixture_supervisor_transport() -> Result<SpawnedFixtureSupervisorTransport, SessionError> {
    let mut launcher_to_fixture = [0; 2];
    let mut fixture_to_launcher = [0; 2];
    if unsafe { libc::pipe2(launcher_to_fixture.as_mut_ptr(), libc::O_CLOEXEC) } < 0
        || unsafe { libc::pipe2(fixture_to_launcher.as_mut_ptr(), libc::O_CLOEXEC) } < 0
    {
        return Err(SessionError::WorkerSpawnFailed);
    }
    Ok(SpawnedFixtureSupervisorTransport {
        handle: FixtureSupervisorTransportHandle {
            reader: unsafe { File::from_raw_fd(fixture_to_launcher[0]) },
            writer: unsafe { File::from_raw_fd(launcher_to_fixture[1]) },
        },
        child_read_fd: launcher_to_fixture[0],
        child_write_fd: fixture_to_launcher[1],
    })
}

fn spawn_writer(stdin: ChildStdin, request: WorkerRequest) -> (JoinHandle<()>, Receiver<Result<(), SessionError>>) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut stdin = stdin;
        let _ = sender.send(write_envelope(&mut stdin, request));
    });
    (handle, receiver)
}
