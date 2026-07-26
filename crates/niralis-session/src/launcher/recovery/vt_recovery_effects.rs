use super::vt_verification::validate_vt_identity;
use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedRecoveryVtTarget {
    boot_id: BootIdentity,
    record_id: String,
    lifecycle_id: String,
    sequence: u64,
    identity: SupervisorVtIdentity,
    active_vt: u32,
    owner_generation: u64,
    boundary_sequence: u64,
}

impl ValidatedRecoveryVtTarget {
    pub(crate) fn from_identity(
        snapshot: &RecoveryStateSnapshot,
        identity: SupervisorVtIdentity,
        proof: &AuthorizedRecoveryBoundaryProof,
        owner: &AuthoritySnapshot,
    ) -> Result<Self, SupervisorRecoveryError> {
        validate_vt_identity(&identity)?;
        if !snapshot.validates()
            || !proof.matches_snapshot(snapshot)
            || identity.seat != snapshot.record.seat
            || Some(identity.number) != snapshot.record.target_vt
            || Some(identity.previous.number) != snapshot.record.previous_vt
        {
            return Err(SupervisorRecoveryError::VtIdentityChanged);
        }
        Ok(Self {
            boot_id: snapshot.authority.boot_id().clone(),
            record_id: snapshot.record.lifecycle_id.clone(),
            lifecycle_id: snapshot.record.lifecycle_id.clone(),
            sequence: snapshot.record.sequence,
            active_vt: snapshot.record.previous_vt.unwrap_or_default(),
            identity,
            owner_generation: owner.generation,
            boundary_sequence: snapshot.record.sequence,
        })
    }

    fn matches_authority(&self, authority: &SameBootRecoveryAuthority) -> bool {
        self.boot_id == *authority.boot_id()
            && self.record_id == authority.lifecycle_id()
            && self.lifecycle_id == authority.lifecycle_id()
            && self.sequence == authority.record_sequence()
    }
}

pub(crate) struct SameBootVtEffects;

impl SameBootVtEffects {
    pub(crate) fn recover(
        authority: &SameBootRecoveryAuthority,
        target: ValidatedRecoveryVtTarget,
        proof: &AuthorizedRecoveryBoundaryProof,
        permit: VtRecoveryPermit,
        owner_watch: &OwnerWatch,
        owner: &AuthoritySnapshot,
    ) -> Result<(), SupervisorRecoveryError> {
        if !target.matches_authority(authority)
            || target.boundary_sequence != target.sequence
            || target.active_vt != target.identity.previous.number
            || target.owner_generation != owner.generation
            || !permit.matches_binding(
                authority,
                &target.record_id,
                &target.lifecycle_id,
                target.sequence,
                &target.boot_id,
            )
            || !proof.matches_binding(
                &target.boot_id,
                &target.record_id,
                &target.lifecycle_id,
                target.sequence,
            )
        {
            return Err(SupervisorRecoveryError::VtIdentityChanged);
        }
        owner_watch
            .still_authorizes(owner)
            .map_err(|_| SupervisorRecoveryError::SystemdOwnerChanged)?;
        let result = super::recover_virtual_terminal_raw(&target.identity);
        if owner_watch.still_authorizes(owner).is_err() {
            return Err(SupervisorRecoveryError::BusDeliveryIndeterminate);
        }
        result
    }
}
