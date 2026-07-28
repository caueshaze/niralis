use super::*;
use std::sync::{Arc, Mutex, OnceLock};

mod filesystem;
mod proc_identity;
mod startup;
mod store;
#[cfg(test)]
mod tests;
mod types;

pub(crate) use filesystem::{
    allow_non_root_test_storage, create_lock_parent, create_secure_directory, load_records,
    sync_directory, validate_lifecycle_id, validate_record,
};
pub(crate) use proc_identity::{
    inspect_worker_identity, kill_exact_pid, proc_executable, proc_starttime,
};
pub(crate) use types::{
    PreCommitRecordFileIdentity, PreCommitRuntimeAuthority, PreCommitRuntimeBinding,
    PreCommitRuntimeRecord, PreCommitRuntimeStore, WorkerIdentityStatus,
    DEFAULT_PRECOMMIT_RUNTIME_DIR, DEFAULT_PRECOMMIT_RUNTIME_LOCK, MAX_PRECOMMIT_RECORD_BYTES,
    PRECOMMIT_FORMAT_VERSION,
};

static PROCESS_RUNTIME_STORE: OnceLock<Arc<Mutex<PreCommitRuntimeStore>>> = OnceLock::new();

pub(crate) fn install_process_runtime_store(store: Arc<Mutex<PreCommitRuntimeStore>>) {
    let _ = PROCESS_RUNTIME_STORE.set(store);
}

pub(crate) fn process_runtime_store() -> Option<&'static Arc<Mutex<PreCommitRuntimeStore>>> {
    PROCESS_RUNTIME_STORE.get()
}
