use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::PathBuf;

pub(crate) const PRECOMMIT_FORMAT_VERSION: u32 = 1;
pub(crate) const MAX_PRECOMMIT_RECORD_BYTES: u64 = 32 * 1024;
pub(crate) const DEFAULT_PRECOMMIT_RUNTIME_DIR: &str = "/run/niralis/admission";
pub(crate) const DEFAULT_PRECOMMIT_RUNTIME_LOCK: &str = "/run/niralis/admission.lock";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreCommitRuntimeRecord {
    pub(crate) format_version: u32,
    pub(crate) transaction_id: String,
    pub(crate) admission_attempt_id: u64,
    pub(crate) lifecycle_id: String,
    pub(crate) seat: String,
    pub(crate) seat_generation: u64,
    pub(crate) boot_id: String,
    pub(crate) stage: String,
    pub(crate) worker_pid: Option<u32>,
    pub(crate) worker_starttime: Option<u64>,
    pub(crate) worker_executable: Option<(u64, u64)>,
    pub(crate) channel_worker_id: Option<String>,
    pub(crate) sequence: u64,
    #[serde(default)]
    pub(crate) handoff_committed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreCommitRuntimeBinding {
    pub(super) authority: PreCommitRuntimeAuthority,
    pub(super) record: PreCommitRuntimeRecord,
}

impl PreCommitRuntimeBinding {
    pub(crate) fn lifecycle_id(&self) -> &str {
        &self.authority.lifecycle_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreCommitRuntimeAuthority {
    pub(super) lifecycle_id: String,
    pub(super) seat_generation: u64,
    pub(super) boot_id: String,
    pub(super) sequence: u64,
    pub(super) file: PreCommitRecordFileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreCommitRecordFileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) links: u64,
}

#[derive(Debug)]
pub(crate) struct PreCommitRuntimeStore {
    pub(super) directory: PathBuf,
    pub(super) _lock: File,
    pub(super) records: BTreeMap<String, PreCommitRuntimeRecord>,
    pub(super) startup_quarantined: bool,
    pub(super) startup_quarantined_seats: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerIdentityStatus {
    Absent,
    Exact,
    Indeterminate,
}
