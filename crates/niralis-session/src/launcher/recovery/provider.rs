use super::*;

pub(crate) trait SupervisorRecoveryProvider: Send + Sync + fmt::Debug {
    fn capture_previous_vt(
        &self,
        seat: &str,
    ) -> Result<PreviousVtIdentity, SupervisorRecoveryError>;

    #[allow(clippy::too_many_arguments)]
    fn prepare_payload(
        &self,
        identity: &crate::PayloadScopeIdentity,
        authoritative_leader_pid: u32,
        worker_pid: u32,
        launcher_pid: u32,
        previous_vt: &PreviousVtIdentity,
    ) -> Result<SupervisorPreparedPayload, SupervisorRecoveryError>;

    fn recover_pre_payload(
        &self,
        worker_pid: u32,
        expected_username: &str,
        session_name: &str,
        previous_vt: &PreviousVtIdentity,
    ) -> Result<SupervisorPrePayloadRecoveryResult, SupervisorRecoveryError>;

    fn cleanup_logind(
        &self,
        identity: &SupervisorLogindSessionIdentity,
    ) -> Result<SupervisorLogindCleanupResult, SupervisorRecoveryError>;

    fn confirm_logind_absent(
        &self,
        identity: &SupervisorLogindSessionIdentity,
    ) -> Result<bool, SupervisorRecoveryError>;

    fn recover_vt(&self, identity: &SupervisorVtIdentity) -> Result<(), SupervisorRecoveryError>;
}
