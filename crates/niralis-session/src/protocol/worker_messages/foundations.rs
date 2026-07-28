use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{LogindSessionId, SessionRequest, StartedSession, WorkerSecret};

/// Version 14 carries transaction-owned PAM prompts before launch commit.
pub const WORKER_PROTOCOL_VERSION: u32 = 14;
pub const MAX_WORKER_MESSAGE_BYTES: usize = 64 * 1024;
/// Version 7 carries transaction-owned PAM responses on the supervisor channel.
pub const WORKER_CONTROL_PROTOCOL_VERSION: u32 = 7;
pub const MAX_WORKER_CONTROL_MESSAGE_BYTES: usize = 4096;
/// Private inherited descriptor used for supervisor lifecycle traffic; stdin remains a one-shot WorkerRequest transport and is expected to reach EOF.
pub const WORKER_SUPERVISOR_FD_ENV: &str = "NIRALIS_WORKER_SUPERVISOR_FD";
pub const FIXTURE_SUPERVISOR_TRANSPORT_ENV: &str = "NIRALIS_FIXTURE_SUPERVISOR_TRANSPORT";
pub const FIXTURE_SUPERVISOR_READ_FD_ENV: &str = "NIRALIS_FIXTURE_SUPERVISOR_READ_FD";
pub const FIXTURE_SUPERVISOR_WRITE_FD_ENV: &str = "NIRALIS_FIXTURE_SUPERVISOR_WRITE_FD";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerEnvelope<T> {
    pub version: u32,
    pub message: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionExecPlan {
    pub source_path: Vec<u8>,
    pub executable: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExecPlanValidationError {
    InvalidShape,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerTransactionIdentity {
    pub transaction_id: String,
    pub admission_attempt_id: u64,
    pub lifecycle_id: String,
    pub seat: String,
    pub seat_generation: u64,
    pub stage: String,
}

/// Identity carried on the control channel while admission still owns cleanup.
/// Transport identifiers deliberately stay outside this capability: they bind a
/// peer, but cannot authorize a transaction transition by themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlTransactionIdentity {
    pub transaction_id: String,
    pub admission_attempt_id: u64,
    pub lifecycle_id: String,
    pub seat: String,
    pub seat_generation: u64,
    pub stage: String,
    pub sequence: u64,
}

impl ControlTransactionIdentity {
    pub fn from_worker(identity: &WorkerTransactionIdentity, stage: &str, sequence: u64) -> Self {
        Self {
            transaction_id: identity.transaction_id.clone(),
            admission_attempt_id: identity.admission_attempt_id,
            lifecycle_id: identity.lifecycle_id.clone(),
            seat: identity.seat.clone(),
            seat_generation: identity.seat_generation,
            stage: stage.into(),
            sequence,
        }
    }

    pub fn matches_worker(&self, identity: &WorkerTransactionIdentity, stage: &str, sequence: u64) -> bool {
        self.transaction_id == identity.transaction_id
            && self.admission_attempt_id == identity.admission_attempt_id
            && self.lifecycle_id == identity.lifecycle_id
            && self.seat == identity.seat
            && self.seat_generation == identity.seat_generation
            && self.stage == stage
            && self.sequence == sequence
    }
}

impl SessionExecPlan {
    pub const MAX_ARGC: usize = 64;
    pub const MAX_ARG_BYTES: usize = 4096;
    pub const MAX_ARGV_BYTES: usize = 16 * 1024;

    pub fn validate(&self) -> Result<(), SessionExecPlanValidationError> {
        if self.source_path.is_empty()
            || self.source_path.len() > 4096
            || self.executable.is_empty()
            || self.executable.len() > 4096
            || self.source_path.contains(&0)
            || self.executable.contains(&0)
            || self.argv.is_empty()
            || self.argv.len() > Self::MAX_ARGC
            || self
                .argv
                .iter()
                .any(|arg| arg.is_empty() || arg.len() > Self::MAX_ARG_BYTES || arg.contains(&0))
            || self.argv.iter().map(|arg| arg.len() + 1).sum::<usize>() > Self::MAX_ARGV_BYTES
        {
            return Err(SessionExecPlanValidationError::InvalidShape);
        }
        let executable = std::path::Path::new(std::ffi::OsStr::from_bytes(&self.executable));
        if !executable.is_absolute() {
            return Err(SessionExecPlanValidationError::InvalidShape);
        }
        Ok(())
    }
}
