use super::super::previous_boot_inspection::*;
use super::types::*;
use std::collections::BTreeMap;

#[cfg(any(test, feature = "supervisor-test-fixtures"))]
#[derive(Debug, Default)]
pub(crate) struct ControlledPreviousBootInspectionHost {
    pub(crate) boot: Option<BootIdentity>,
    pub(crate) conflicts: CurrentBootConflictFacts,
    pub(crate) seats: BTreeMap<String, CurrentSeatFacts>,
    pub(crate) vts: BTreeMap<u32, CurrentVtFacts>,
    pub(crate) calls: std::sync::Mutex<Vec<&'static str>>,
    pub(crate) authority_stable: bool,
}

#[cfg(any(test, feature = "supervisor-test-fixtures"))]
impl PreviousBootInspectionHost for ControlledPreviousBootInspectionHost {
    fn current_boot_identity(&self) -> Result<BootIdentity, PreviousBootInspectionError> {
        self.calls.lock().unwrap().push("boot");
        self.boot
            .clone()
            .ok_or(PreviousBootInspectionError::Unavailable)
    }
    fn inspect_current_conflicts(
        &self,
        _: &PreviousBootConflictRequest,
    ) -> Result<CurrentBootConflictFacts, PreviousBootInspectionError> {
        self.calls.lock().unwrap().push("conflicts");
        Ok(self.conflicts.clone())
    }
    fn inspect_current_seat(
        &self,
        seat: &str,
    ) -> Result<CurrentSeatFacts, PreviousBootInspectionError> {
        self.calls.lock().unwrap().push("seat");
        self.seats
            .get(seat)
            .cloned()
            .ok_or(PreviousBootInspectionError::Unavailable)
    }
    fn inspect_current_vt(&self, vt: u32) -> Result<CurrentVtFacts, PreviousBootInspectionError> {
        self.calls.lock().unwrap().push("vt");
        self.vts
            .get(&vt)
            .cloned()
            .ok_or(PreviousBootInspectionError::Unavailable)
    }

    fn inspect_current_snapshot(
        &self,
        request: &PreviousBootInspectionRequest,
    ) -> Result<PreviousBootCurrentFacts, PreviousBootInspectionError> {
        self.calls.lock().unwrap().push("snapshot");
        let boot = self
            .boot
            .clone()
            .ok_or(PreviousBootInspectionError::Unavailable)?;
        if !self.authority_stable {
            return Err(PreviousBootInspectionError::AuthorityChanged);
        }
        let mut facts = PreviousBootCurrentFacts {
            authority: CurrentAuthorityFacts {
                systemd_owner: Some("controlled-systemd".to_owned()),
                systemd_generation: Some(0),
                logind_owner: Some("controlled-logind".to_owned()),
                logind_generation: Some(0),
                stable: true,
            },
            conflicts: self.conflicts.clone(),
            ..PreviousBootCurrentFacts::default()
        };
        facts.seat = self
            .seats
            .get(&request.record.record.seat)
            .cloned()
            .ok_or(PreviousBootInspectionError::Unavailable)?;
        facts.vt = request
            .record
            .record
            .target_vt
            .and_then(|vt| self.vts.get(&vt).cloned());
        facts.has_newer_record_for_seat = request.records.iter().any(|other| {
            other.seat == request.record.record.seat
                && other.sequence > request.record.record.sequence
        });
        facts.has_same_boot_record_for_seat = request.records.iter().any(|other| {
            other.seat == request.record.record.seat && other.created_boot_id == boot.as_str()
        });
        Ok(facts)
    }
}

#[cfg(feature = "supervisor-test-fixtures")]
pub(crate) fn controlled_previous_boot_host_for_fixture_linkage() {
    let _ = std::mem::size_of::<ControlledPreviousBootInspectionHost>();
}
