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

    fn ownership(runtime: &str, logind: &str) -> RuntimeOwnership {
        RuntimeOwnership {
            runtime_id: RuntimeSessionId::new(runtime.to_owned()),
            logind_session_id: crate::LogindSessionId::new(logind.to_owned()).unwrap(),
            payload_scope: crate::PayloadScopeIdentity {
                unit_name: format!("niralis-payload-{runtime}.scope"),
                invocation_id: "0123456789abcdef0123456789abcdef".into(),
                expected_uid: 1000,
                logind_session_id: crate::LogindSessionId::new(logind.to_owned()).unwrap(),
            },
        }
    }

    #[test]
    fn swap_remove_removes_only_the_matching_runtime_logind_pair() {
        let a = ownership("runtime-a", "c1");
        let b = ownership("runtime-b", "c2");
        let mut active = vec![a.clone(), b.clone()];
        let index = active
            .iter()
            .position(|value| value.runtime_id == a.runtime_id)
            .unwrap();
        let removed = active.swap_remove(index);
        assert_eq!(removed, a);
        assert_eq!(active, vec![b]);
    }

    #[test]
    fn expired_runtime_id_cannot_match_a_future_ownership() {
        let expired = ownership("runtime-a", "c1");
        let future = ownership("runtime-b", "c2");
        assert_ne!(expired.runtime_id, future.runtime_id);
        assert_ne!(expired.logind_session_id, future.logind_session_id);
    }

    fn identity() -> crate::PayloadScopeIdentity {
        crate::PayloadScopeIdentity {
            unit_name: "niralis-payload-release-test.scope".into(),
            invocation_id: "0123456789abcdef0123456789abcdef".into(),
            expected_uid: 1000,
            logind_session_id: crate::LogindSessionId::new("c1".into()).unwrap(),
        }
    }

    fn registered_supervisor() -> (WorkerSupervisor, crate::PayloadScopeIdentity) {
        let supervisor = WorkerSupervisor::new();
        supervisor.begin_pending("worker-release", 4242).unwrap();
        let scope = identity();
        supervisor
            .record_prepared_scope("worker-release", 4242, scope.clone(), "reg-1".into())
            .unwrap();
        (supervisor, scope)
    }

    #[test]
    fn release_verification_removes_only_matching_registered_lifecycle() {
        let (supervisor, scope) = registered_supervisor();
        let token = supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: scope,
            })
            .unwrap();
        supervisor
            .complete_release(token, crate::ScopeReleaseVerification::Released)
            .unwrap();
        assert!(supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: identity(),
            })
            .is_err());
    }

    #[test]
    fn failed_release_verification_retains_recovery_state() {
        let (supervisor, scope) = registered_supervisor();
        let token = supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: scope,
            })
            .unwrap();
        supervisor
            .complete_release(
                token,
                crate::ScopeReleaseVerification::RecoveryRequired(
                    crate::PayloadScopeRecoveryReason::MembershipNotEmpty,
                ),
            )
            .unwrap();
        assert!(supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: identity(),
            })
            .is_err());
    }

    #[test]
    fn divergent_release_identity_is_rejected() {
        let (supervisor, _) = registered_supervisor();
        let mut other = identity();
        other.invocation_id = "fedcba9876543210fedcba9876543210".into();
        assert!(supervisor
            .begin_release(ReleaseRequest {
                worker_id: "worker-release".into(),
                worker_pid: 4242,
                registration_nonce: "reg-1".into(),
                release_nonce: "release-1".into(),
                identity: other,
            })
            .is_err());
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

fn terminate_group(pgid: u32, signal: i32) -> Result<(), SessionError> {
    if pgid == 0 || pgid > i32::MAX as u32 {
        return Err(SessionError::WorkerIoFailed);
    }
    let result = unsafe { libc::kill(-(pgid as libc::pid_t), signal) };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(SessionError::WorkerIoFailed)
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
