use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentScopeFacts {
    pub(crate) unit_name: String,
    pub(crate) object_path: String,
    pub(crate) invocation_id: String,
    pub(crate) control_group: String,
    pub(crate) slice: String,
    pub(crate) transient: bool,
    pub(crate) active_state: String,
    pub(crate) sub_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentSessionFacts {
    pub(crate) session_id: String,
    pub(crate) object_path: String,
    pub(crate) seat: String,
    pub(crate) leader_pid: u32,
    pub(crate) vt: u32,
    pub(crate) state: String,
    pub(crate) scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HistoricalIdentityCollision {
    pub(crate) pid: u32,
    pub(crate) historical_starttime: Option<u64>,
    pub(crate) current_starttime: Option<u64>,
    pub(crate) historical_executable: Option<(u64, u64)>,
    pub(crate) current_executable: Option<(u64, u64)>,
    pub(crate) current_cgroup: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreviousBootConflictRequest {
    pub(crate) lifecycle_id: String,
    pub(crate) payload_unit: Option<String>,
    pub(crate) invocation_id: Option<String>,
    pub(crate) control_group: Option<String>,
    pub(crate) logind_session_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreviousBootInspectionRequest {
    pub(crate) record: PreviousBootRecoveryRecord,
    pub(crate) records: Vec<PersistentRecoveryRecord>,
}

impl From<&PreviousBootRecoveryRecord> for PreviousBootConflictRequest {
    fn from(record: &PreviousBootRecoveryRecord) -> Self {
        Self {
            lifecycle_id: record.record.lifecycle_id.clone(),
            payload_unit: record.record.payload_unit.clone(),
            invocation_id: record.record.invocation_id.clone(),
            control_group: record.record.control_group.clone(),
            logind_session_id: record.record.logind_session_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreviousBootInspectionError {
    InvalidBootIdentity,
    Unavailable,
    AuthorityChanged,
}

/// Read-only seam. Effectful adapters are deliberately absent from this trait.
pub(crate) trait PreviousBootInspectionHost: std::fmt::Debug + Send + Sync {
    fn current_boot_identity(&self) -> Result<BootIdentity, PreviousBootInspectionError>;
    fn inspect_current_conflicts(
        &self,
        request: &PreviousBootConflictRequest,
    ) -> Result<CurrentBootConflictFacts, PreviousBootInspectionError>;
    fn inspect_current_seat(
        &self,
        seat: &str,
    ) -> Result<CurrentSeatFacts, PreviousBootInspectionError>;
    fn inspect_current_vt(&self, vt: u32) -> Result<CurrentVtFacts, PreviousBootInspectionError>;

    fn inspect_current_snapshot(
        &self,
        request: &PreviousBootInspectionRequest,
    ) -> Result<PreviousBootCurrentFacts, PreviousBootInspectionError> {
        let conflicts = self.inspect_current_conflicts(&(&request.record).into())?;
        let mut facts = PreviousBootCurrentFacts {
            conflicts,
            ..Default::default()
        };
        facts.seat = self.inspect_current_seat(&request.record.record.seat)?;
        facts.vt = request
            .record
            .record
            .target_vt
            .map(|vt| self.inspect_current_vt(vt))
            .transpose()?;
        facts.has_newer_record_for_seat = request.records.iter().any(|other| {
            other.seat == request.record.record.seat
                && other.lifecycle_id != request.record.record.lifecycle_id
                && other.sequence > request.record.record.sequence
        });
        facts.has_same_boot_record_for_seat = request.records.iter().any(|other| {
            other.seat == request.record.record.seat
                && other.created_boot_id == request.record.current_boot.as_str()
        });
        Ok(facts)
    }
}
