
fn emit_fixture_cause(cause: &crate::termination::TerminationCause) {
    use crate::termination::{TerminationCause, WorkerTerminationSignal};

    let event = match cause {
        TerminationCause::WorkerSignal(WorkerTerminationSignal::Sigterm) => "Cause:Sigterm",
        TerminationCause::WorkerSignal(WorkerTerminationSignal::Sigint) => "Cause:Sigint",
        TerminationCause::WorkerSignal(WorkerTerminationSignal::Sighup) => "Cause:Sighup",
        TerminationCause::SupervisorDisconnected => "Cause:SupervisorDisconnected",
        TerminationCause::InternalTerminateRequest => "Cause:InternalTerminateRequest",
        TerminationCause::LeaderExited(_) => "Cause:LeaderExited",
        TerminationCause::RuntimeFailure => "Cause:RuntimeFailure",
    };
    emit_fixture_event(event);
}

fn emit_fixture_launch_signal(signal: i32) {
    let name = match signal {
        libc::SIGTERM => "SIGTERM",
        libc::SIGINT => "SIGINT",
        libc::SIGHUP => "SIGHUP",
        _ => "UNKNOWN",
    };
    emit_fixture_event(&format!("LaunchCancellationSignal:{name}"));
}

fn worker_signal_fd() -> i32 {
    WORKER_SIGNAL_FD.get()
}
fn supervisor_channel_fd() -> i32 {
    SUPERVISOR_CHANNEL_FD.get()
}
fn set_worker_signal_fd(fd: i32) -> i32 {
    WORKER_SIGNAL_FD.replace(fd)
}
fn set_supervisor_channel_fd(fd: i32) -> i32 {
    SUPERVISOR_CHANNEL_FD.replace(fd)
}

fn duplicate_supervisor_channel() -> Result<UnixStream, SessionError> {
    let fd = supervisor_channel_fd();
    if fd < 0 {
        return Err(SessionError::WorkerProtocolFailed);
    }
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(SessionError::WorkerIoFailed);
    }
    Ok(unsafe { UnixStream::from_raw_fd(duplicate) })
}

fn supervisor_peer_matches(expected_uid: u32, expected_pid: u32) -> bool {
    duplicate_supervisor_channel()
        .ok()
        .and_then(|stream| peer_credentials(&stream))
        .is_some_and(|credentials| {
            credentials.uid == expected_uid && credentials.pid as u32 == expected_pid
        })
}

pub fn run_worker_process_with_signals<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    signals: &crate::termination::WorkerSignalFd,
    supervisor_fd: RawFd,
) -> Result<(), SessionError> {
    run_worker_process_with_dependencies_and_signals(
        reader,
        writer,
        signals,
        supervisor_fd,
        WorkerDependencies {
            authenticator_factory: &PamAuthenticatorFactory,
            identity_resolver: &NssUnixIdentityResolver,
            supplementary_groups_resolver: &NssSupplementaryGroupsResolver,
            session_child_runner_factory: &ProcessSessionChildRunnerFactory,
            logind_resolver: &SdLoginResolver,
            virtual_terminal_allocator: &LinuxVirtualTerminalAllocator,
            runtime_dir_validator: &LinuxRuntimeDirValidator,
            selinux_context_manager: &LinuxSelinuxContextManager,
            payload_scope_manager: &crate::payload_scope::SystemdPayloadScopeManager,
            launch_phase_gate: &NoopLaunchPhaseGate,
        },
    )
}

pub(crate) fn run_worker_process_with_dependencies_and_signals<
    R: Read,
    W: Write,
    F: WorkerAuthenticatorFactory,
    I: UnixIdentityResolver,
    G: SupplementaryGroupsResolver,
    C: SessionChildRunnerFactory,
    L: LogindSessionResolver,
>(
    reader: &mut R,
    writer: &mut W,
    signals: &crate::termination::WorkerSignalFd,
    supervisor_fd: RawFd,
    dependencies: WorkerDependencies<'_, F, I, G, C, L>,
) -> Result<(), SessionError> {
    let previous = set_worker_signal_fd(signals.as_raw_fd());
    let previous_supervisor = set_supervisor_channel_fd(supervisor_fd);
    let result = run_worker_process_with_dependencies(reader, writer, dependencies);
    set_worker_signal_fd(previous);
    set_supervisor_channel_fd(previous_supervisor);
    result
}

pub fn take_inherited_supervisor_channel() -> Result<UnixStream, SessionError> {
    let value = std::env::var_os(niralis_session::WORKER_SUPERVISOR_FD_ENV)
        .ok_or(SessionError::WorkerProtocolFailed)?;
    std::env::remove_var(niralis_session::WORKER_SUPERVISOR_FD_ENV);
    let fd = value
        .to_str()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or(SessionError::WorkerProtocolFailed)?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(SessionError::WorkerProtocolFailed);
    }
    let mut socket_type: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
        || socket_type != libc::SOCK_STREAM
    {
        return Err(SessionError::WorkerProtocolFailed);
    }
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}
