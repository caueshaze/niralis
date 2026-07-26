pub(crate) use super::super::previous_boot_inspection::{
    CurrentScopeFacts, CurrentSessionFacts, HistoricalIdentityCollision,
};
use super::super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BootIdentity(String);

impl BootIdentity {
    pub(crate) fn parse(value: impl Into<String>) -> Result<Self, PreviousBootInspectionError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(PreviousBootInspectionError::InvalidBootIdentity);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Debug, Clone)]
pub(crate) struct SameBootRecoveryRecord {
    pub(crate) record: PersistentRecoveryRecord,
    pub(crate) current_boot: BootIdentity,
}
#[derive(Debug, Clone)]
pub(crate) struct PreviousBootRecoveryRecord {
    pub(crate) record: PersistentRecoveryRecord,
    pub(crate) recorded_boot: BootIdentity,
    pub(crate) current_boot: BootIdentity,
}

#[derive(Debug, Clone)]
pub(crate) enum RecoveryRecordEpoch {
    SameBoot(SameBootRecoveryRecord),
    PreviousBoot(PreviousBootRecoveryRecord),
}

impl RecoveryRecordEpoch {
    pub(crate) fn classify(
        record: PersistentRecoveryRecord,
        current_boot: BootIdentity,
    ) -> Result<Self, PreviousBootInspectionError> {
        let recorded_boot = BootIdentity::parse(record.created_boot_id.clone())?;
        if recorded_boot == current_boot {
            Ok(Self::SameBoot(SameBootRecoveryRecord {
                record,
                current_boot,
            }))
        } else {
            Ok(Self::PreviousBoot(PreviousBootRecoveryRecord {
                record,
                recorded_boot,
                current_boot,
            }))
        }
    }
}

/// Capability for recovery adapters that can affect the host; private fields prevent forgery.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SameBootRecoveryAuthority {
    current_boot: BootIdentity,
    record_boot: BootIdentity,
    lifecycle_id: String,
    record_sequence: u64,
}

impl SameBootRecoveryRecord {
    pub(crate) fn destructive_authority(&self) -> SameBootRecoveryAuthority {
        SameBootRecoveryAuthority::from_record(&self.current_boot, &self.record)
            .expect("SameBoot record was classified with a valid boot identity")
    }

    pub(crate) fn snapshot(&self) -> RecoveryStateSnapshot {
        RecoveryStateSnapshot {
            record: self.record.clone(),
            authority: self.destructive_authority(),
        }
    }
}

impl SameBootRecoveryAuthority {
    pub(crate) fn from_record(
        current_boot: &BootIdentity,
        record: &PersistentRecoveryRecord,
    ) -> Result<Self, PreviousBootInspectionError> {
        Ok(Self {
            current_boot: current_boot.clone(),
            record_boot: BootIdentity::parse(record.created_boot_id.clone())?,
            lifecycle_id: record.lifecycle_id.clone(),
            record_sequence: record.sequence,
        })
    }
    pub(crate) fn boot_id(&self) -> &BootIdentity {
        &self.current_boot
    }
    pub(crate) fn current_boot(&self) -> &BootIdentity {
        &self.current_boot
    }
    pub(crate) fn record_sequence(&self) -> u64 {
        self.record_sequence
    }
    pub(crate) fn lifecycle_id(&self) -> &str {
        &self.lifecycle_id
    }
    pub(crate) fn validates(&self, record: &PersistentRecoveryRecord) -> bool {
        self.current_boot == self.record_boot
            && self.record_boot.as_str() == record.created_boot_id
            && self.lifecycle_id == record.lifecycle_id
            && self.record_sequence == record.sequence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreviousBootOperationPolicy {
    HistoricalConfirmed,
    HistoricalFailed,
    HistoricalIndeterminateNeverReplay,
    CurrentBootInspectionRequired,
    EligibleForReadOnlyResolutionPlanning,
}

pub(crate) fn previous_boot_operation_policy(
    state: DurableOperationState,
) -> PreviousBootOperationPolicy {
    match state {
        DurableOperationState::Confirmed { .. } => PreviousBootOperationPolicy::HistoricalConfirmed,
        DurableOperationState::Failed { .. } => PreviousBootOperationPolicy::HistoricalFailed,
        DurableOperationState::IntentPersisted { .. }
        | DurableOperationState::Indeterminate { .. } => {
            PreviousBootOperationPolicy::HistoricalIndeterminateNeverReplay
        }
        DurableOperationState::NotStarted => {
            PreviousBootOperationPolicy::EligibleForReadOnlyResolutionPlanning
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CurrentIdentityObservation {
    Absent,
    PresentButDifferentIdentity,
    PresentAndConflicting,
    Ambiguous,
    InspectionUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentBootConflictFacts {
    pub(crate) same_unit_name: CurrentIdentityObservation,
    pub(crate) same_invocation_id: CurrentIdentityObservation,
    pub(crate) same_cgroup_path: CurrentIdentityObservation,
    pub(crate) same_session_id: CurrentIdentityObservation,
    pub(crate) same_lifecycle_id: CurrentIdentityObservation,
}

impl Default for CurrentBootConflictFacts {
    fn default() -> Self {
        Self {
            same_unit_name: CurrentIdentityObservation::Absent,
            same_invocation_id: CurrentIdentityObservation::Absent,
            same_cgroup_path: CurrentIdentityObservation::Absent,
            same_session_id: CurrentIdentityObservation::Absent,
            same_lifecycle_id: CurrentIdentityObservation::Absent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CurrentAuthorityFacts {
    pub(crate) systemd_owner: Option<String>,
    pub(crate) systemd_generation: Option<u64>,
    pub(crate) logind_owner: Option<String>,
    pub(crate) logind_generation: Option<u64>,
    pub(crate) stable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CurrentSeatRuntimeState {
    Unclaimed,
    ClaimedByCurrentLifecycle,
    QuarantinedByCurrentRecord,
    Conflicting,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentSeatFacts {
    pub(crate) runtime_state: CurrentSeatRuntimeState,
    pub(crate) inspection_complete: bool,
    pub(crate) active_lifecycle: Option<String>,
    pub(crate) sessions: Vec<CurrentSessionFacts>,
    pub(crate) scopes: Vec<CurrentScopeFacts>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CurrentVtDisposition {
    NotForegroundAndUnused,
    Foreground,
    UsedByCurrentLifecycle,
    VisibleCurrentHolder,
    Ambiguous,
    InspectionUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentVtFacts {
    pub(crate) target_vt: u32,
    pub(crate) active_vt: Option<u32>,
    pub(crate) disposition: CurrentVtDisposition,
    pub(crate) inspection_complete: bool,
    pub(crate) visible_holders: Vec<crate::VtHolderIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PreviousBootCurrentFacts {
    pub(crate) authority: CurrentAuthorityFacts,
    pub(crate) conflicts: CurrentBootConflictFacts,
    pub(crate) seat: CurrentSeatFacts,
    pub(crate) scopes: Vec<CurrentScopeFacts>,
    pub(crate) sessions: Vec<CurrentSessionFacts>,
    pub(crate) historical_pid_reuse: Vec<HistoricalIdentityCollision>,
    pub(crate) vt: Option<CurrentVtFacts>,
    pub(crate) competing_records: Vec<String>,
    pub(crate) inspection_failures: Vec<PreviousBootInspectionError>,
    pub(crate) has_newer_record_for_seat: bool,
    pub(crate) has_same_boot_record_for_seat: bool,
    pub(crate) ambiguous_neighbor: bool,
}

impl Default for CurrentSeatFacts {
    fn default() -> Self {
        Self {
            runtime_state: CurrentSeatRuntimeState::Unknown,
            inspection_complete: false,
            active_lifecycle: None,
            sessions: Vec::new(),
            scopes: Vec::new(),
        }
    }
}
