pub(crate) use super::persistent_record_set::*;
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CorruptionReason {
    Truncated,
    InvalidJson,
    Oversized,
    MissingRequiredField,
    InvalidBootId,
    InvalidOperationLedger,
    InvalidNumericRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnsafeMetadataReason {
    Symlink,
    NonRegularFile,
    LinkCount,
    WrongOwner,
    UnsafeMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordIdentityMismatch {
    FilenameRecordId,
    DuplicateRecordId,
    DuplicateLifecycle,
    ConflictingSeat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HistoricalInvariantViolation {
    SequenceRegression,
    AttemptIdZero,
    AttemptIdRegression,
    DuplicateAttemptId,
    ResultWithoutIntent,
    ConflictingTerminalResult,
    OperationAfterRecordResolved,
    RuntimeReleaseBeforeRecordResolved,
    RecordRemovalBeforeRuntimeRelease,
    AcknowledgementCrossedBoot,
    InvalidBootId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordConflictReason {
    DuplicateRecordId,
    DuplicateLifecycle,
    SameSeatSameBootPrecedence,
    CorruptNeighborKnownSeat,
    UnknownVersionNeighbor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DurableRecoveryRecordReadResult {
    ValidSameBoot {
        path: PathBuf,
        record: PersistentRecoveryRecord,
    },
    ValidPreviousBoot {
        path: PathBuf,
        record: PersistentRecoveryRecord,
    },
    Corrupted {
        path: PathBuf,
        reason: CorruptionReason,
    },
    UnsupportedVersion {
        path: PathBuf,
        version: u64,
    },
    UnsafeMetadata {
        path: PathBuf,
        reason: UnsafeMetadataReason,
    },
    IdentityMismatch {
        path: PathBuf,
        reason: RecordIdentityMismatch,
    },
    HistoricalInvariantViolation {
        path: PathBuf,
        violations: Vec<HistoricalInvariantViolation>,
    },
    ConflictingRecords {
        path: PathBuf,
        reason: RecordConflictReason,
    },
}

impl DurableRecoveryRecordReadResult {
    pub(crate) fn path(&self) -> &Path {
        match self {
            Self::ValidSameBoot { path, .. }
            | Self::ValidPreviousBoot { path, .. }
            | Self::Corrupted { path, .. }
            | Self::UnsupportedVersion { path, .. }
            | Self::UnsafeMetadata { path, .. }
            | Self::IdentityMismatch { path, .. }
            | Self::HistoricalInvariantViolation { path, .. }
            | Self::ConflictingRecords { path, .. } => path,
        }
    }

    pub(crate) fn record(&self) -> Option<&PersistentRecoveryRecord> {
        match self {
            Self::ValidSameBoot { record, .. } | Self::ValidPreviousBoot { record, .. } => {
                Some(record)
            }
            _ => None,
        }
    }

    pub(crate) fn known_seat(&self) -> Option<&str> {
        self.record().map(|record| record.seat.as_str())
    }
}

pub(crate) fn validate_historical_record(
    record: &PersistentRecoveryRecord,
) -> Vec<HistoricalInvariantViolation> {
    let mut violations = Vec::new();
    if record.sequence == 0 {
        violations.push(HistoricalInvariantViolation::SequenceRegression);
    }
    if BootIdentity::parse(record.created_boot_id.clone()).is_err()
        || BootIdentity::parse(record.last_updated_boot_id.clone()).is_err()
    {
        violations.push(HistoricalInvariantViolation::InvalidBootId);
    }
    let states = [
        record.operation_ledger.payload_kill,
        record.operation_ledger.supervisor_unref,
        record.operation_ledger.logind_termination,
        record.operation_ledger.selinux_restore,
        record.operation_ledger.vt_activation,
        record.operation_ledger.vt_disallocate,
        record.operation_ledger.record_resolution,
        record.operation_ledger.runtime_release,
    ];
    let attempts = states
        .into_iter()
        .filter_map(|state| match state {
            DurableOperationState::NotStarted => None,
            DurableOperationState::IntentPersisted { attempt_id }
            | DurableOperationState::Confirmed { attempt_id }
            | DurableOperationState::Failed { attempt_id, .. }
            | DurableOperationState::Indeterminate { attempt_id, .. } => Some(attempt_id),
        })
        .collect::<Vec<_>>();
    if attempts.contains(&0) {
        violations.push(HistoricalInvariantViolation::AttemptIdZero);
        violations.push(HistoricalInvariantViolation::ResultWithoutIntent);
    }
    if attempts.windows(2).any(|window| window[1] < window[0]) {
        violations.push(HistoricalInvariantViolation::AttemptIdRegression);
    }
    let mut unique = attempts.clone();
    unique.sort_unstable();
    if unique.windows(2).any(|window| window[0] == window[1]) {
        violations.push(HistoricalInvariantViolation::DuplicateAttemptId);
    }
    if matches!(
        record.operation_ledger.runtime_release,
        DurableOperationState::Confirmed { .. }
    ) && record.state != "record_resolved"
    {
        violations.push(HistoricalInvariantViolation::RuntimeReleaseBeforeRecordResolved);
    }
    if record.state == "record_resolved"
        && !matches!(
            record.operation_ledger.record_resolution,
            DurableOperationState::Confirmed { .. } | DurableOperationState::NotStarted
        )
    {
        violations.push(HistoricalInvariantViolation::OperationAfterRecordResolved);
    }
    if matches!(
        record.operation_ledger.record_resolution,
        DurableOperationState::Confirmed { .. }
    ) && record.state != "record_resolved"
    {
        violations.push(HistoricalInvariantViolation::OperationAfterRecordResolved);
    }
    let mut vt_attempts = record.vt_recovery_attempts.iter().collect::<Vec<_>>();
    vt_attempts.sort_by_key(|attempt| attempt.attempt_id);
    if vt_attempts
        .iter()
        .any(|attempt| attempt.attempt_id == 0 || attempt.expected_sequence == 0)
    {
        violations.push(HistoricalInvariantViolation::AttemptIdZero);
    }
    if vt_attempts.windows(2).any(|window| {
        window[1].attempt_id <= window[0].attempt_id
            || window[1].expected_sequence <= window[0].expected_sequence
    }) {
        violations.push(HistoricalInvariantViolation::AttemptIdRegression);
    }
    for pair in vt_attempts.windows(2) {
        if pair[0].attempt_id == pair[1].attempt_id && pair[0].state != pair[1].state {
            violations.push(HistoricalInvariantViolation::ConflictingTerminalResult);
        }
    }
    if record.vt_recovery_attempts.iter().any(|attempt| {
        matches!(
            attempt.state,
            crate::VtRecoveryAttemptState::Confirmed
                | crate::VtRecoveryAttemptState::Failed { .. }
                | crate::VtRecoveryAttemptState::Indeterminate
        ) && !matches!(
            record.operation_ledger.vt_disallocate,
            DurableOperationState::Confirmed { .. }
                | DurableOperationState::Failed { .. }
                | DurableOperationState::Indeterminate { .. }
        )
    }) {
        violations.push(HistoricalInvariantViolation::ResultWithoutIntent);
    }
    violations.sort_by_key(|violation| format!("{violation:?}"));
    violations.dedup();
    violations
}

pub(crate) fn persistent_taxonomy_is_complete() {
    let _ = UnsafeMetadataReason::NonRegularFile;
    let _ = RecordIdentityMismatch::DuplicateLifecycle;
    let _ = RecordIdentityMismatch::ConflictingSeat;
    let _ = HistoricalInvariantViolation::RecordRemovalBeforeRuntimeRelease;
    let _ = HistoricalInvariantViolation::AcknowledgementCrossedBoot;
    let _ = RecordConflictReason::CorruptNeighborKnownSeat;
    let _ = RecordConflictReason::UnknownVersionNeighbor;
    let _ = DurableRecoveryRecordReadResult::ConflictingRecords {
        path: PathBuf::new(),
        reason: RecordConflictReason::DuplicateRecordId,
    };
}
