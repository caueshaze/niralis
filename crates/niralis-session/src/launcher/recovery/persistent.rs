use super::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::MetadataExt;

pub(crate) const RECOVERY_FORMAT_VERSION: u32 = 1;
pub(crate) const MAX_RECOVERY_RECORD_BYTES: u64 = 128 * 1024;
pub(crate) const MAX_RECOVERY_RECORDS: usize = 64;
pub(crate) const DEFAULT_RECOVERY_DIR: &str = "/var/lib/niralis/recovery";
pub(crate) const DEFAULT_RECOVERY_LOCK: &str = "/run/niralis/recovery.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryBootRelation {
    SameBoot,
    PreviousBoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DurableOperationState {
    NotStarted,
    IntentPersisted { attempt_id: u64 },
    Confirmed { attempt_id: u64 },
    Failed { attempt_id: u64, failure_class: i32 },
    Indeterminate { attempt_id: u64, stage: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableOperationLedger {
    pub(crate) payload_kill: DurableOperationState,
    pub(crate) supervisor_unref: DurableOperationState,
    pub(crate) logind_termination: DurableOperationState,
    pub(crate) selinux_restore: DurableOperationState,
    pub(crate) vt_activation: DurableOperationState,
    pub(crate) vt_disallocate: DurableOperationState,
    pub(crate) runtime_release: DurableOperationState,
    pub(crate) record_resolution: DurableOperationState,
}

impl Default for DurableOperationLedger {
    fn default() -> Self {
        let state = DurableOperationState::NotStarted;
        Self {
            payload_kill: state,
            supervisor_unref: state,
            logind_termination: state,
            selinux_restore: state,
            vt_activation: state,
            vt_disallocate: state,
            runtime_release: state,
            record_resolution: state,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistentRecoveryRecord {
    pub(crate) format_version: u32,
    pub(crate) lifecycle_id: String,
    pub(crate) sequence: u64,
    pub(crate) created_at_unix: u64,
    pub(crate) created_boot_id: String,
    pub(crate) last_updated_boot_id: String,
    pub(crate) state: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) username: String,
    pub(crate) session_name: String,
    pub(crate) seat: String,
    pub(crate) worker_pid: u32,
    pub(crate) launcher_pid: u32,
    pub(crate) worker_starttime: Option<u64>,
    pub(crate) worker_executable: Option<(u64, u64)>,
    pub(crate) worker_cgroup: Option<String>,
    pub(crate) leader_pid: Option<u32>,
    pub(crate) leader_starttime: Option<u64>,
    pub(crate) leader_executable: Option<(u64, u64)>,
    pub(crate) payload_unit: Option<String>,
    pub(crate) transient: Option<bool>,
    pub(crate) invocation_id: Option<String>,
    pub(crate) object_path: Option<String>,
    pub(crate) control_group: Option<String>,
    pub(crate) slice: Option<String>,
    pub(crate) logind_session_id: Option<String>,
    pub(crate) logind_object_path: Option<String>,
    pub(crate) target_vt: Option<u32>,
    pub(crate) previous_vt: Option<u32>,
    pub(crate) pam_status: String,
    pub(crate) operation_ledger: DurableOperationLedger,
    pub(crate) quarantine_reason: Option<String>,
}

impl PersistentRecoveryRecord {
    pub(crate) fn prepared(
        id: &str,
        worker_pid: u32,
        launcher_pid: u32,
        user: &str,
        session: &str,
        previous: &PreviousVtIdentity,
        payload: &SupervisorPreparedPayload,
    ) -> Self {
        let boot = current_boot_id().unwrap_or_else(|_| "unavailable".to_owned());
        let identity = payload.boundary.identity();
        Self {
            format_version: RECOVERY_FORMAT_VERSION,
            lifecycle_id: id.to_owned(),
            sequence: 1,
            created_at_unix: current_unix_time(),
            created_boot_id: boot.clone(),
            last_updated_boot_id: boot,
            state: "payload_prepared".to_owned(),
            uid: identity.expected_uid,
            gid: payload.target_gid,
            username: user.to_owned(),
            session_name: session.to_owned(),
            seat: payload.vt.seat.clone(),
            worker_pid,
            launcher_pid,
            worker_starttime: proc_starttime(worker_pid),
            worker_executable: proc_executable(worker_pid),
            worker_cgroup: proc_cgroup(worker_pid),
            leader_pid: Some(payload.boundary.leader_pid()),
            leader_starttime: proc_starttime(payload.boundary.leader_pid()),
            leader_executable: proc_executable(payload.boundary.leader_pid()),
            payload_unit: Some(identity.unit_name.clone()),
            transient: Some(true),
            invocation_id: Some(identity.invocation_id.clone()),
            object_path: payload.boundary.object_path().map(str::to_owned),
            control_group: payload.boundary.control_group().map(str::to_owned),
            slice: payload.boundary.slice().map(str::to_owned),
            logind_session_id: Some(identity.logind_session_id.as_str().to_owned()),
            logind_object_path: Some(payload.logind.object_path.clone()),
            target_vt: Some(payload.vt.number),
            previous_vt: Some(previous.number),
            pam_status: "opened_by_worker".to_owned(),
            operation_ledger: DurableOperationLedger::default(),
            quarantine_reason: None,
        }
    }

    pub(crate) fn transition(&mut self, state: &str) -> Result<(), &'static str> {
        if state.is_empty() || state.len() > 64 || state.as_bytes().contains(&0) {
            return Err("invalid durable state");
        }
        self.sequence = self.sequence.checked_add(1).ok_or("sequence overflow")?;
        self.state = state.to_owned();
        self.last_updated_boot_id = current_boot_id().map_err(|_| "boot id unavailable")?;
        Ok(())
    }
}

pub(crate) fn current_boot_id() -> std::io::Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}
fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |v| v.as_secs())
}
fn proc_starttime(pid: u32) -> Option<u64> {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()?
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
fn proc_executable(pid: u32) -> Option<(u64, u64)> {
    fs::metadata(format!("/proc/{pid}/exe"))
        .ok()
        .map(|m| (m.dev(), m.ino()))
}
fn proc_cgroup(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
}

#[path = "persistent_storage.rs"]
mod persistent_storage;
pub(crate) use persistent_storage::*;

#[cfg(test)]
#[path = "persistent_tests.rs"]
mod persistent_tests;
