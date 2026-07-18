use super::*;

#[derive(Debug, Default)]
pub(crate) struct LinuxSupervisorRecoveryProvider;

impl SupervisorRecoveryProvider for LinuxSupervisorRecoveryProvider {
    fn capture_previous_vt(
        &self,
        seat: &str,
    ) -> Result<PreviousVtIdentity, SupervisorRecoveryError> {
        if seat != "seat0" {
            return Err(SupervisorRecoveryError::VtIdentityChanged);
        }
        let active = fs::read_to_string("/sys/class/tty/tty0/active")
            .map_err(|_| SupervisorRecoveryError::VtIdentityChanged)?;
        let number = active
            .trim()
            .strip_prefix("tty")
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| (1..=63).contains(value))
            .ok_or(SupervisorRecoveryError::VtIdentityChanged)?;
        Ok(PreviousVtIdentity { number })
    }

    fn prepare_payload(
        &self,
        identity: &crate::PayloadScopeIdentity,
        authoritative_leader_pid: u32,
        worker_pid: u32,
        launcher_pid: u32,
        previous_vt: &PreviousVtIdentity,
    ) -> Result<SupervisorPreparedPayload, SupervisorRecoveryError> {
        let leader = SupervisorLeaderPidfd::open(authoritative_leader_pid)?;
        let pin = SupervisorPinnedInvocationUnit::acquire(
            identity.clone(),
            authoritative_leader_pid,
            worker_pid,
            launcher_pid,
            &leader,
        )?;
        let logind = resolve_logind_identity(identity, authoritative_leader_pid)?;
        if logind.uid != identity.expected_uid
            || logind.id != identity.logind_session_id
            || logind.leader != worker_pid
            || logind.seat != "seat0"
            || logind.vt_number == previous_vt.number
        {
            return Err(SupervisorRecoveryError::LogindIdentityChanged);
        }
        let (target_uid, target_gid) = read_process_credentials(authoritative_leader_pid)?;
        if target_uid != identity.expected_uid {
            return Err(SupervisorRecoveryError::InvalidPayloadIdentity);
        }
        let vt = SupervisorVtIdentity {
            seat: logind.seat.clone(),
            number: logind.vt_number,
            previous: previous_vt.clone(),
            device_major: 4,
            device_minor: logind.vt_number,
        };
        Ok(SupervisorPreparedPayload {
            boundary: Box::new(LinuxSupervisorPayloadBoundary { pin, leader }),
            logind,
            vt,
            target_gid,
        })
    }

    fn recover_pre_payload(
        &self,
        worker_pid: u32,
        expected_username: &str,
        session_name: &str,
        previous_vt: &PreviousVtIdentity,
    ) -> Result<SupervisorPrePayloadRecoveryResult, SupervisorRecoveryError> {
        let identity = resolve_logind_identity_by_leader(worker_pid, session_name)?;
        if identity.username != expected_username || identity.vt_number == previous_vt.number {
            return Err(SupervisorRecoveryError::VtIdentityChanged);
        }
        let vt = SupervisorVtIdentity {
            seat: identity.seat.clone(),
            number: identity.vt_number,
            previous: previous_vt.clone(),
            device_major: 4,
            device_minor: identity.vt_number,
        };
        let logind_result = cleanup_logind_session(&identity)?;
        recover_virtual_terminal(&vt)?;
        Ok(SupervisorPrePayloadRecoveryResult { logind_result })
    }

    fn cleanup_logind(
        &self,
        identity: &SupervisorLogindSessionIdentity,
    ) -> Result<SupervisorLogindCleanupResult, SupervisorRecoveryError> {
        cleanup_logind_session(identity)
    }

    fn confirm_logind_absent(
        &self,
        identity: &SupervisorLogindSessionIdentity,
    ) -> Result<bool, SupervisorRecoveryError> {
        logind_session_absent(identity)
    }

    fn recover_vt(&self, identity: &SupervisorVtIdentity) -> Result<(), SupervisorRecoveryError> {
        recover_virtual_terminal(identity)
    }
}

#[derive(Debug)]
pub(crate) struct SupervisorLeaderPidfd {
    pub(crate) pid: u32,
    pub(crate) pidfd: OwnedFd,
}

impl SupervisorLeaderPidfd {
    pub(crate) fn open(pid: u32) -> Result<Self, SupervisorRecoveryError> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(SupervisorRecoveryError::LeaderPidfdUnavailable);
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd < 0 {
            return Err(SupervisorRecoveryError::LeaderPidfdUnavailable);
        }
        let value = Self {
            pid,
            pidfd: unsafe { OwnedFd::from_raw_fd(fd as RawFd) },
        };
        if value.observed_dead()? {
            return Err(SupervisorRecoveryError::LeaderAlreadyDead);
        }
        Ok(value)
    }

    pub(crate) fn observed_dead(&self) -> Result<bool, SupervisorRecoveryError> {
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 {
            Err(SupervisorRecoveryError::LeaderPidfdUnavailable)
        } else {
            Ok(result > 0 && descriptor.revents & libc::POLLIN != 0)
        }
    }
}
