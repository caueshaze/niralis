use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedRecoveryLogindSession {
    boot_id: BootIdentity,
    record_id: String,
    lifecycle_id: String,
    sequence: u64,
    seat: String,
    id: crate::LogindSessionId,
    object_path: String,
    owner_generation: u64,
    identity: SupervisorLogindSessionIdentity,
}

impl ValidatedRecoveryLogindSession {
    pub(crate) fn from_identity(
        snapshot: &RecoveryStateSnapshot,
        identity: SupervisorLogindSessionIdentity,
        owner: &AuthoritySnapshot,
    ) -> Result<Self, SupervisorRecoveryError> {
        let record = &snapshot.record;
        if !snapshot.validates()
            || identity.id.as_str() != record.logind_session_id.as_deref().unwrap_or_default()
            || identity.object_path != record.logind_object_path.clone().unwrap_or_default()
            || identity.seat != record.seat
            || identity.leader != record.worker_pid
            || Some(identity.vt_number) != record.target_vt
        {
            return Err(SupervisorRecoveryError::LogindIdentityChanged);
        }
        Ok(Self {
            boot_id: snapshot.authority.boot_id().clone(),
            record_id: record.lifecycle_id.clone(),
            lifecycle_id: record.lifecycle_id.clone(),
            sequence: record.sequence,
            seat: identity.seat.clone(),
            id: identity.id.clone(),
            object_path: identity.object_path.clone(),
            owner_generation: owner.generation,
            identity,
        })
    }

    fn matches_authority(&self, authority: &SameBootRecoveryAuthority) -> bool {
        self.boot_id == *authority.boot_id()
            && self.record_id == authority.lifecycle_id()
            && self.lifecycle_id == authority.lifecycle_id()
            && self.sequence == authority.record_sequence()
    }

    pub(crate) fn as_identity(&self) -> SupervisorLogindSessionIdentity {
        self.identity.clone()
    }
}

pub(crate) struct SameBootLogindEffects;

impl SameBootLogindEffects {
    pub(crate) fn terminate_session(
        authority: &SameBootRecoveryAuthority,
        target: ValidatedRecoveryLogindSession,
        permit: LogindCleanupPermit,
        owner_watch: &OwnerWatch,
        owner: &AuthoritySnapshot,
    ) -> Result<SupervisorLogindCleanupResult, SupervisorRecoveryError> {
        if !target.matches_authority(authority)
            || !permit.matches_binding(
                authority,
                &target.record_id,
                &target.lifecycle_id,
                target.sequence,
                &target.boot_id,
            )
            || target.owner_generation != owner.generation
        {
            return Err(SupervisorRecoveryError::LogindIdentityChanged);
        }
        owner_watch
            .still_authorizes(owner)
            .map_err(|_| SupervisorRecoveryError::LogindOwnerChanged)?;
        let result = super::terminate_logind_session_raw(&target.as_identity())?;
        if owner_watch.still_authorizes(owner).is_err() {
            return Err(SupervisorRecoveryError::LogindCleanupIndeterminate);
        }
        Ok(result)
    }
}
