use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RecoveryBoundaryEmptyProof {
    boot_id: BootIdentity,
    record_id: String,
    lifecycle_id: String,
    record_sequence: u64,
    invocation_id: String,
    control_group: String,
    owner_generation: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthorizedRecoveryBoundaryProof {
    proof: RecoveryBoundaryEmptyProof,
    authorized_sequence: u64,
}

impl RecoveryBoundaryEmptyProof {
    pub(crate) fn from_absent_boundary(snapshot: &RecoveryStateSnapshot) -> Self {
        Self {
            boot_id: snapshot.authority.boot_id().clone(),
            record_id: snapshot.record.lifecycle_id.clone(),
            lifecycle_id: snapshot.record.lifecycle_id.clone(),
            record_sequence: snapshot.record.sequence,
            invocation_id: snapshot.record.invocation_id.clone().unwrap_or_default(),
            control_group: snapshot.record.control_group.clone().unwrap_or_default(),
            owner_generation: 0,
        }
    }

    pub(crate) fn from_verified_boundary(
        snapshot: &RecoveryStateSnapshot,
        pin: &RecoveryPinnedInvocationUnit,
    ) -> Self {
        Self {
            boot_id: snapshot.authority.boot_id().clone(),
            record_id: snapshot.record.lifecycle_id.clone(),
            lifecycle_id: snapshot.record.lifecycle_id.clone(),
            record_sequence: snapshot.record.sequence,
            invocation_id: snapshot.record.invocation_id.clone().unwrap_or_default(),
            control_group: pin.control_group().to_owned(),
            owner_generation: pin.owner_generation(),
        }
    }

    pub(crate) fn matches_snapshot(&self, snapshot: &RecoveryStateSnapshot) -> bool {
        self.boot_id == *snapshot.authority.boot_id()
            && self.record_id == snapshot.record.lifecycle_id
            && self.lifecycle_id == snapshot.record.lifecycle_id
            && self.record_sequence == snapshot.record.sequence
            && self.invocation_id == snapshot.record.invocation_id.clone().unwrap_or_default()
            && self.control_group == snapshot.record.control_group.clone().unwrap_or_default()
    }

    pub(crate) fn authorize(self, sequence: u64) -> AuthorizedRecoveryBoundaryProof {
        AuthorizedRecoveryBoundaryProof {
            authorized_sequence: sequence,
            proof: Self {
                record_sequence: sequence,
                ..self
            },
        }
    }
}

impl AuthorizedRecoveryBoundaryProof {
    pub(crate) fn authorize_next_sequence(&self, sequence: u64) -> Self {
        Self {
            proof: RecoveryBoundaryEmptyProof {
                boot_id: self.proof.boot_id.clone(),
                record_id: self.proof.record_id.clone(),
                lifecycle_id: self.proof.lifecycle_id.clone(),
                record_sequence: sequence,
                invocation_id: self.proof.invocation_id.clone(),
                control_group: self.proof.control_group.clone(),
                owner_generation: self.proof.owner_generation,
            },
            authorized_sequence: sequence,
        }
    }

    pub(crate) fn matches_binding(
        &self,
        boot: &BootIdentity,
        record_id: &str,
        lifecycle_id: &str,
        sequence: u64,
    ) -> bool {
        self.authorized_sequence == sequence
            && self.proof.boot_id == *boot
            && self.proof.record_id == record_id
            && self.proof.lifecycle_id == lifecycle_id
            && self.proof.record_sequence == sequence
    }

    pub(crate) fn matches_snapshot(&self, snapshot: &RecoveryStateSnapshot) -> bool {
        self.authorized_sequence == snapshot.record.sequence
            && self.proof.boot_id == *snapshot.authority.boot_id()
            && self.proof.record_id == snapshot.record.lifecycle_id
            && self.proof.lifecycle_id == snapshot.record.lifecycle_id
            && self.proof.invocation_id == snapshot.record.invocation_id.clone().unwrap_or_default()
            && self.proof.control_group == snapshot.record.control_group.clone().unwrap_or_default()
    }

    pub(crate) fn matches_pin(
        &self,
        record: &PersistentRecoveryRecord,
        pin: &RecoveryPinnedInvocationUnit,
    ) -> bool {
        self.authorized_sequence == record.sequence
            && self.proof.record_sequence == record.sequence
            && self.proof.invocation_id == pin.invocation_id()
            && self.proof.control_group == pin.control_group()
            && self.proof.owner_generation == pin.owner_generation()
    }
}
