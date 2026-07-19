use super::*;

pub(crate) const EMERGENCY_BOUNDARY_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const LOGIND_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupRecoveryDecision {
    ObserveSurvivingWorker,
    ResumeEmergencyRecovery,
    ResumeAfterBoundaryProof,
    ResumeLogindCleanup,
    ResumeVtRecovery,
    PreserveQuarantine,
    ClearPreviousBootRecord,
    Quarantine(StartupRecoveryFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupRecoveryFailure {
    UnsupportedRehydration,
    PersistentRecordConflict,
    BoundaryIdentityChanged,
    WorkerIdentityIndeterminate,
    LeaderIdentityIndeterminate,
    SystemdOwnerChanged,
    LogindOwnerChanged,
    LogindIdentityChanged,
    PreviousBootConflict,
    UnknownPayloadScope,
    VtDisallocateBusy,
}

impl StartupRecoveryFailure {
    pub(crate) const fn persistent_reason(self) -> &'static str {
        match self {
            Self::UnsupportedRehydration => "unsupported_rehydration",
            Self::PersistentRecordConflict => "persistent_record_conflict",
            Self::BoundaryIdentityChanged => "boundary_identity_changed",
            Self::WorkerIdentityIndeterminate => "worker_identity_indeterminate",
            Self::LeaderIdentityIndeterminate => "leader_identity_indeterminate",
            Self::SystemdOwnerChanged => "systemd_owner_changed",
            Self::LogindOwnerChanged => "logind_owner_changed",
            Self::LogindIdentityChanged => "logind_identity_changed",
            Self::PreviousBootConflict => "previous_boot_conflict",
            Self::UnknownPayloadScope => "unknown_payload_scope",
            Self::VtDisallocateBusy => "vt_disallocate_busy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupRecoveryOutcome {
    Free,
    Quarantined(StartupRecoveryFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerExitClassification {
    CleanFinalization,
    FailedAfterBoundaryCleanup,
    UnexpectedExitBeforeStarted,
    UnexpectedExitRunning,
    KilledBySignal(i32),
    RecoveryGateLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PamEmergencyCleanupStatus {
    UnavailableAfterWorkerDeath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmergencyRecoveryStage {
    RecoveryRecordValidation,
    PayloadIdentityValidation,
    EmergencyKill,
    BoundaryObservation,
    BoundaryProof,
    SupervisorUnref,
    LogindCleanup,
    SelinuxTtyRestore,
    VtRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SupervisorLogindCleanupResult {
    Removed,
    AlreadyGone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SupervisorEmergencyBoundaryProof {
    pub(crate) unit_name: String,
    pub(crate) invocation_id: String,
    pub(crate) control_group: String,
    pub(crate) worker_exit: String,
    pub(crate) leader_observed_dead: bool,
    pub(crate) cgroup_observed_empty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SupervisorEmergencyContainmentProof {
    PayloadBoundary(SupervisorEmergencyBoundaryProof),
    NoPayloadScopeWasRegistered { worker_exit: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SupervisorEmergencyRecoveryOutcome {
    Recovered {
        containment_proof: SupervisorEmergencyContainmentProof,
        logind_result: SupervisorLogindCleanupResult,
        pam_status: PamEmergencyCleanupStatus,
    },
    Quarantined {
        stage: EmergencyRecoveryStage,
        reason: SupervisorRecoveryError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SupervisorRecoveryError {
    InvalidRecord,
    InvalidPayloadIdentity,
    BoundaryIdentityChanged,
    BusUnavailable,
    BusDeliveryIndeterminate,
    LeaderPidfdUnavailable,
    LeaderAlreadyDead,
    LeaderStillAlive,
    BoundaryStillPopulated,
    BoundaryObserverUnavailable,
    BoundaryTimedOut,
    SupervisorUnrefFailed,
    LogindUnavailable,
    LogindIdentityChanged,
    LogindRemovalTimedOut,
    VtIdentityChanged,
    VtOpenFailed(i32),
    VtKernelRestoreFailed(i32),
    SelinuxRestoreFailed(i32),
    VtActivationFailed(i32),
    VtDisallocateBusy,
    VtDisallocateFailed(i32),
    PersistentRecordConflict,
    WorkerIdentityIndeterminate,
    LeaderIdentityIndeterminate,
    SystemdOwnerChanged,
    LogindOwnerChanged,
    PreviousBootConflict,
    UnknownPayloadScope,
    UnsupportedStartupRecovery,
}

impl SupervisorRecoveryError {
    pub(crate) fn from_persistent_quarantine(reason: Option<&str>, state: &str) -> Self {
        match reason {
            Some("persistent_record_conflict") => Self::PersistentRecordConflict,
            Some("boundary_identity_changed") => Self::BoundaryIdentityChanged,
            Some("worker_identity_indeterminate") => Self::WorkerIdentityIndeterminate,
            Some("leader_identity_indeterminate") => Self::LeaderIdentityIndeterminate,
            Some("systemd_owner_changed") => Self::SystemdOwnerChanged,
            Some("logind_owner_changed") => Self::LogindOwnerChanged,
            Some("logind_identity_changed") => Self::LogindIdentityChanged,
            Some("previous_boot_conflict") => Self::PreviousBootConflict,
            Some("unknown_payload_scope") => Self::UnknownPayloadScope,
            Some("vt_disallocate_busy") | None if state == "vt_disallocate_failed_busy" => {
                Self::VtDisallocateBusy
            }
            _ => Self::UnsupportedStartupRecovery,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreviousVtIdentity {
    pub(crate) number: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SupervisorLogindSessionIdentity {
    pub(crate) id: crate::LogindSessionId,
    pub(crate) object_path: String,
    pub(crate) uid: u32,
    pub(crate) username: String,
    pub(crate) leader: u32,
    pub(crate) seat: String,
    pub(crate) vt_number: u32,
    pub(crate) session_type: String,
    pub(crate) class: String,
    pub(crate) desktop: String,
    pub(crate) state: String,
    pub(crate) scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SupervisorVtIdentity {
    pub(crate) seat: String,
    pub(crate) number: u32,
    pub(crate) previous: PreviousVtIdentity,
    pub(crate) device_major: u32,
    pub(crate) device_minor: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SupervisorPrePayloadRecoveryResult {
    pub(crate) logind_result: SupervisorLogindCleanupResult,
}
