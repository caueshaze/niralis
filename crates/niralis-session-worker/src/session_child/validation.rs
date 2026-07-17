
fn open_pidfd(pid: u32) -> Option<OwnedFd> {
    if pid == 0 || pid > libc::pid_t::MAX as u32 {
        return None;
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        None
    } else {
        Some(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }
}

fn validate_ready_response(
    response: SessionChildResponse,
    expectation: &SessionChildExpectation,
    pid: u32,
    allows_status_pipe: bool,
) -> Result<SessionChildReport, SessionChildError> {
    let mut allowed_inherited_fds = expectation
        .terminal
        .as_ref()
        .map_or_else(Vec::new, |terminal| vec![terminal.fd]);
    if allows_status_pipe {
        allowed_inherited_fds.push(4);
    }
    match response {
        SessionChildResponse::Ready {
            canonical_username,
            session_id,
            child_pid,
            applied_credentials,
            credential_proof,
            isolation_proof,
            process_identity,
            runtime_environment,
            exec_probe_version,
            terminal_proof,
        } if canonical_username == expectation.canonical_username
            && session_id == expectation.session_id
            && child_pid == pid
            && applied_credentials
                == SessionChildUnixCredentials::from(&expectation.target_credentials)
            && {
                let proof = PostDropIsolationProof::from(isolation_proof.clone());
                let present_allowed_fds = allowed_inherited_fds
                    .iter()
                    .copied()
                    .filter(|fd| proof.open_fds.binary_search(fd).is_ok())
                    .collect::<Vec<_>>();
                validate_isolation_proof_with_allowed_fds(&proof, &present_allowed_fds).is_ok()
            }
            && credential_proof.real_uid == expectation.target_credentials.uid
            && credential_proof.effective_uid == expectation.target_credentials.uid
            && credential_proof.saved_uid == expectation.target_credentials.uid
            && credential_proof.real_gid == expectation.target_credentials.gid
            && credential_proof.effective_gid == expectation.target_credentials.gid
            && credential_proof.saved_gid == expectation.target_credentials.gid
            && normalized_groups(
                credential_proof.supplementary_gids.clone(),
                expectation.target_credentials.gid,
            ) == expectation.target_credentials.supplementary_gids
            && exec_probe_version == SESSION_EXEC_PROBE_VERSION
            && process_identity.pid == pid
            && process_identity.sid == pid
            && process_identity.pgid == pid
            && runtime_environment.home == expectation.runtime.home
            && runtime_environment.shell == expectation.runtime.shell
            && runtime_environment.session_type == expectation.runtime.session_type
            && (expectation.runtime.session_id.is_empty()
                || (runtime_environment.session_class == expectation.runtime.session_class
                    && runtime_environment.session_desktop
                        == expectation.runtime.session_desktop
                    && runtime_environment.session_id == expectation.runtime.session_id
                    && runtime_environment.runtime_dir == expectation.runtime.runtime_dir
                    && runtime_environment.seat == expectation.runtime.seat
                    && runtime_environment.vtnr == expectation.runtime.vtnr
                    && runtime_environment.dbus_session_bus_address
                        == expectation.runtime.dbus_session_bus_address
                    && runtime_environment.imported_locale
                        == expectation.runtime.imported_locale
                    && runtime_environment.forbidden_variables_present.is_empty()
                    && runtime_environment.user_bus_connected))
            && runtime_environment.user == expectation.canonical_username
            && runtime_environment.logname == expectation.canonical_username
            && runtime_environment.path == DEFAULT_SESSION_PATH
            && runtime_environment.cwd == expectation.runtime.home
            && (expectation.runtime.session_id.is_empty()
                || runtime_environment.exec_plan == expectation.runtime.exec_plan)
            && match (&expectation.terminal, &terminal_proof) {
                (None, None) => true,
                (Some(expected), Some(actual)) => {
                    actual.seat == expected.seat
                        && actual.vtnr == expected.vtnr
                        && actual.fd == expected.fd
                        && actual.device_major == expected.device_major
                        && actual.device_minor == expected.device_minor
                        && actual.controlling_sid == pid
                        && actual.foreground_pgid == pid
                }
                _ => false,
            } =>
        {
            Ok(SessionChildReport {
                canonical_username,
                session_id,
                child_pid,
                applied_credentials: AppliedCredentials {
                    uid: applied_credentials.uid,
                    gid: applied_credentials.gid,
                    supplementary_gids: applied_credentials.supplementary_gids,
                },
                isolation_proof: isolation_proof.into(),
                process_identity: ProcessIdentityProof {
                    pid: process_identity.pid,
                    sid: process_identity.sid,
                    pgid: process_identity.pgid,
                },
                runtime_environment: RuntimeEnvironmentProof {
                    home: runtime_environment.home,
                    user: runtime_environment.user,
                    logname: runtime_environment.logname,
                    shell: runtime_environment.shell,
                    path: runtime_environment.path,
                    session_type: runtime_environment.session_type,
                    session_class: runtime_environment.session_class,
                    session_desktop: runtime_environment.session_desktop,
                    session_id: runtime_environment.session_id,
                    runtime_dir: runtime_environment.runtime_dir,
                    seat: runtime_environment.seat,
                    vtnr: runtime_environment.vtnr,
                    dbus_session_bus_address: runtime_environment.dbus_session_bus_address,
                    imported_locale: runtime_environment.imported_locale,
                    forbidden_variables_present: runtime_environment.forbidden_variables_present,
                    user_bus_connected: runtime_environment.user_bus_connected,
                    cwd: runtime_environment.cwd,
                    exec_plan: runtime_environment.exec_plan,
                },
                exec_probe_version,
                credential_proof,
                terminal_proof,
            })
        }
        SessionChildResponse::Rejected { .. } => Err(SessionChildError::ProtocolFailed),
        SessionChildResponse::Ready {
            canonical_username,
            session_id,
            child_pid,
            applied_credentials,
            credential_proof,
            isolation_proof,
            process_identity,
            runtime_environment,
            exec_probe_version,
            terminal_proof,
        } => {
            let proof = PostDropIsolationProof::from(isolation_proof.clone());
            let present_allowed_fds = allowed_inherited_fds
                .iter()
                .copied()
                .filter(|fd| proof.open_fds.binary_search(fd).is_ok())
                .collect::<Vec<_>>();
            let credential_proof_matches = credential_proof.real_uid
                == expectation.target_credentials.uid
                && credential_proof.effective_uid == expectation.target_credentials.uid
                && credential_proof.saved_uid == expectation.target_credentials.uid
                && credential_proof.real_gid == expectation.target_credentials.gid
                && credential_proof.effective_gid == expectation.target_credentials.gid
                && credential_proof.saved_gid == expectation.target_credentials.gid
                && normalized_groups(
                    credential_proof.supplementary_gids,
                    expectation.target_credentials.gid,
                ) == expectation.target_credentials.supplementary_gids;
            let terminal_proof_matches = match (&expectation.terminal, &terminal_proof) {
                (None, None) => true,
                (Some(expected), Some(actual)) => {
                    actual.seat == expected.seat
                        && actual.vtnr == expected.vtnr
                        && actual.fd == expected.fd
                        && actual.device_major == expected.device_major
                        && actual.device_minor == expected.device_minor
                        && actual.controlling_sid == pid
                        && actual.foreground_pgid == pid
                }
                _ => false,
            };
            warn!(
                canonical_username_matches = canonical_username == expectation.canonical_username,
                session_id_matches = session_id == expectation.session_id,
                child_pid_matches = child_pid == pid,
                applied_credentials_match = applied_credentials
                    == SessionChildUnixCredentials::from(&expectation.target_credentials),
                credential_proof_matches,
                isolation_proof_valid =
                    validate_isolation_proof_with_allowed_fds(&proof, &present_allowed_fds).is_ok(),
                process_identity_matches = process_identity.pid == pid
                    && process_identity.sid == pid
                    && process_identity.pgid == pid,
                exec_probe_version_matches = exec_probe_version == SESSION_EXEC_PROBE_VERSION,
                runtime_user_matches = runtime_environment.user == expectation.canonical_username
                    && runtime_environment.logname == expectation.canonical_username,
                runtime_path_matches = runtime_environment.path == DEFAULT_SESSION_PATH,
                runtime_cwd_matches = runtime_environment.cwd == expectation.runtime.home,
                terminal_proof_matches,
                "session child Ready response failed strict validation"
            );
            Err(SessionChildError::ProtocolFailed)
        }
    }
}

fn normalized_groups(mut groups: Vec<u32>, primary_gid: u32) -> Vec<u32> {
    groups.sort_unstable();
    groups.dedup();
    groups.retain(|gid| *gid != primary_gid);
    groups
}

pub const DEFAULT_SESSION_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
