use serde::{Deserialize, Serialize};

pub const RECOVERY_ADMIN_PROTOCOL_VERSION: u16 = 1;
pub const MAX_RECOVERY_ADMIN_PACKET_BYTES: usize = 16 * 1024;
pub const MAX_VT_BUSY_HOLDERS: usize = 32;
pub const MAX_VT_INSPECTION_FAILURES: usize = 32;
pub const MAX_VT_RECOVERY_ATTEMPTS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub major: u32,
    pub minor: u32,
    pub character_device: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtHolderIdentity {
    pub pid: u32,
    pub starttime: u64,
    pub uid: u32,
    pub fd: u32,
    pub executable: Option<ExecutableIdentity>,
    pub cgroup: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VtInspectionFailure {
    ActiveVt { errno: i32 },
    TargetDevice { errno: i32 },
    ProcEnumeration { errno: i32 },
    ProcessIdentity { pid: u32, errno: i32 },
    FdInspection { pid: u32, fd: u32, errno: i32 },
    ProcessMetadata { pid: u32, errno: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VtBusyClassification {
    TargetStillForeground,
    VisibleUserspaceHolder,
    MultipleVisibleUserspaceHolders,
    KernelBusyUnattributed,
    InspectionUnavailable,
    InternalNiralisHolder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtBusyProvenance {
    pub target_vt: u32,
    pub observed_active_vt: Option<u32>,
    pub target_is_foreground: Option<bool>,
    pub target_device: Option<DeviceIdentity>,
    pub visible_holders: Vec<VtHolderIdentity>,
    pub holders_truncated: bool,
    pub inspection_failures: Vec<VtInspectionFailure>,
    pub classification: VtBusyClassification,
    pub captured_at_boottime_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VtRecoveryAttemptState {
    IntentPersisted,
    Confirmed,
    Failed { errno: i32 },
    Rejected { reason: String },
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtRecoveryAttempt {
    pub attempt_id: u64,
    pub requested_by: u32,
    pub expected_sequence: u64,
    pub state: VtRecoveryAttemptState,
    pub provenance_before: VtBusyProvenance,
    pub provenance_after: Option<VtBusyProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryVtInspection {
    pub seat: String,
    pub record_id: String,
    pub sequence: u64,
    pub target_vt: u32,
    pub quarantine_reason: Option<String>,
    pub operation_ledger: RecoveryOperationLedger,
    pub provenance: Option<VtBusyProvenance>,
    pub attempts: Vec<VtRecoveryAttempt>,
}

/// Read-only, stable representation of the durable operation ledger exposed by
/// the root-only recovery socket.  Keep this typed: formatting the internal
/// ledger with `Debug` made both the human and JSON interface accidental.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryOperationLedger {
    pub payload_kill: RecoveryOperationState,
    pub supervisor_unref: RecoveryOperationState,
    pub logind_termination: RecoveryOperationState,
    pub selinux_restore: RecoveryOperationState,
    pub vt_activation: RecoveryOperationState,
    pub vt_disallocate: RecoveryOperationState,
    pub runtime_release: RecoveryOperationState,
    pub record_resolution: RecoveryOperationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryOperationState {
    NotStarted,
    IntentPersisted { attempt_id: u64 },
    Confirmed { attempt_id: u64 },
    Failed { attempt_id: u64, failure_class: i32 },
    Indeterminate { attempt_id: u64, stage: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryAdminRequest {
    InspectVt {
        seat: String,
        record_id: String,
    },
    RetryVtDisallocate {
        seat: String,
        record_id: String,
        record_sequence: u64,
        acknowledge_indeterminate: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryAdminResponse {
    Inspection(Box<RecoveryVtInspection>),
    RetryAccepted {
        record_id: String,
        sequence: u64,
        attempt_id: u64,
    },
    Rejected {
        reason: String,
        sequence: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAdminEnvelope<T> {
    pub version: u16,
    pub message: T,
}
