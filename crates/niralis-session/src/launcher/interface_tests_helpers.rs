impl SessionLauncher for WorkerSessionLauncher {
    fn start_session(&self, request: SessionRequest) -> Result<StartedSession, SessionError> {
        self.start_worker(
            WorkerRequest::PrepareSession {
                request: request.clone(),
            },
            expected_started_session(&request),
            true,
        )
        .map(|(session, _)| session)
    }
}

fn expected_started_session(request: &SessionRequest) -> StartedSession {
    StartedSession {
        username: request.username.clone(),
        session: request.session.clone(),
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    #[test]
    fn expired_runtime_id_cannot_match_a_future_lifecycle() {
        let expired = RuntimeSessionId::new("runtime-a".to_owned());
        let future = RuntimeSessionId::new("runtime-b".to_owned());
        assert_ne!(expired, future);
    }
}

fn create_control_endpoint() -> Result<(TempDir, PathBuf, String), SessionError> {
    let root = Path::new("/run/niralis/worker-control");
    let directory = if prepare_control_root(root).is_ok() {
        Builder::new()
            .prefix("worker-")
            .tempdir_in(root)
            .map_err(|_| SessionError::WorkerIoFailed)?
    } else {
        Builder::new()
            .prefix("niralis-worker-control-")
            .tempdir()
            .map_err(|_| SessionError::WorkerIoFailed)?
    };
    let worker_id = directory
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SessionError::WorkerIoFailed)?
        .to_owned();
    let path = directory.path().join("control.sock");
    Ok((directory, path, worker_id))
}

fn prepare_control_root(root: &Path) -> Result<(), SessionError> {
    fs::create_dir_all(root).map_err(|_| SessionError::WorkerIoFailed)?;
    let metadata = fs::symlink_metadata(root).map_err(|_| SessionError::WorkerIoFailed)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.gid() != 0 {
        return Err(SessionError::WorkerIoFailed);
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|_| SessionError::WorkerIoFailed)
}

fn install_control_request(request: &mut WorkerRequest, path: PathBuf, worker_id: String) {
    if let WorkerRequest::PamSession {
        control_path: control,
        worker_id: id,
        launcher_pid,
        ..
    } = request
    {
        *control = path;
        *id = worker_id;
        *launcher_pid = std::process::id();
    }
}

fn map_response(
    response: WorkerEnvelope<WorkerResponse>,
    status: ExitStatus,
    expected: StartedSession,
) -> Result<StartedSession, SessionError> {
    if response.version != crate::WORKER_PROTOCOL_VERSION {
        return Err(SessionError::WorkerProtocolFailed);
    }

    match response.message {
        WorkerResponse::Started { .. } => Err(SessionError::WorkerProtocolFailed),
        WorkerResponse::Ready { session } if status.success() && session == expected => Ok(session),
        WorkerResponse::Ready { .. } => Err(SessionError::WorkerProtocolFailed),
        WorkerResponse::AuthenticationFailed if !status.success() => {
            Err(SessionError::AuthenticationFailed)
        }
        WorkerResponse::SessionFailed { code } if !status.success() => {
            debug!(
                ?code,
                "session worker reported authenticated session failure"
            );
            Err(SessionError::AuthenticatedSessionFailed)
        }
        WorkerResponse::Rejected { code } if !status.success() => {
            debug!(?code, "session worker rejected request");
            Err(SessionError::WorkerRejected)
        }
        _ => Err(SessionError::WorkerProtocolFailed),
    }
}
