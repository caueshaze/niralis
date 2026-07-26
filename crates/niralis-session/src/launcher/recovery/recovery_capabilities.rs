use super::*;
use std::marker::PhantomData;

#[derive(Debug)]
pub(crate) struct RecoveryStateSnapshot {
    pub(crate) record: PersistentRecoveryRecord,
    pub(crate) authority: SameBootRecoveryAuthority,
}

impl RecoveryStateSnapshot {
    pub(crate) fn from_record(
        current_boot: &BootIdentity,
        record: PersistentRecoveryRecord,
    ) -> Result<Self, PreviousBootInspectionError> {
        let authority = SameBootRecoveryAuthority::from_record(current_boot, &record)?;
        Ok(Self { record, authority })
    }

    pub(crate) fn validates(&self) -> bool {
        self.authority.validates(&self.record)
    }

    pub(crate) fn current_boot(&self) -> &BootIdentity {
        self.authority.current_boot()
    }
}

#[derive(Debug)]
pub(crate) struct PayloadKillOperation;
#[derive(Debug)]
pub(crate) struct SupervisorUnrefOperation;
#[derive(Debug)]
pub(crate) struct RuntimeReleaseOperation;
#[derive(Debug)]
pub(crate) struct LogindCleanupOperation;
#[derive(Debug)]
pub(crate) struct VtRecoveryOperation;

pub(crate) type LogindCleanupPermit = RecoveryOperationPermit<LogindCleanupOperation>;
pub(crate) type VtRecoveryPermit = RecoveryOperationPermit<VtRecoveryOperation>;

#[derive(Debug)]
pub(crate) struct RecoveryOperationPermit<K> {
    record_id: String,
    lifecycle_id: String,
    boot_id: BootIdentity,
    sequence: u64,
    attempt_id: u64,
    _kind: PhantomData<K>,
}

impl<K> RecoveryOperationPermit<K> {
    pub(crate) fn attempt_id(&self) -> u64 {
        self.attempt_id
    }

    pub(crate) fn matches(
        &self,
        record: &PersistentRecoveryRecord,
        boot: &BootIdentity,
        attempt_id: u64,
    ) -> bool {
        self.record_id == record.lifecycle_id
            && self.lifecycle_id == record.lifecycle_id
            && self.boot_id.as_str() == boot.as_str()
            && self.sequence == record.sequence
            && self.attempt_id == attempt_id
    }

    pub(crate) fn matches_binding(
        &self,
        authority: &SameBootRecoveryAuthority,
        record_id: &str,
        lifecycle_id: &str,
        sequence: u64,
        boot_id: &BootIdentity,
    ) -> bool {
        self.record_id == record_id
            && self.lifecycle_id == lifecycle_id
            && self.boot_id == *boot_id
            && self.boot_id == *authority.boot_id()
            && authority.record_sequence() == sequence
            && self.sequence == sequence
    }
}

pub(super) fn make_recovery_permit<K>(
    record: &PersistentRecoveryRecord,
    attempt_id: u64,
) -> Result<RecoveryOperationPermit<K>, PreviousBootInspectionError> {
    Ok(RecoveryOperationPermit {
        record_id: record.lifecycle_id.clone(),
        lifecycle_id: record.lifecycle_id.clone(),
        boot_id: BootIdentity::parse(record.created_boot_id.clone())?,
        sequence: record.sequence,
        attempt_id,
        _kind: PhantomData,
    })
}
