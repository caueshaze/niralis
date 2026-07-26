use super::*;
use std::fmt;
use std::io;

#[path = "previous_boot_failpoints.rs"]
mod failpoints;
pub(crate) use failpoints::*;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PreviousBootFinalizationAuthority {
    pub(super) current_boot: BootIdentity,
    pub(super) recorded_boot: BootIdentity,
    pub(super) record_id: String,
    pub(super) lifecycle_id: String,
    pub(super) seat: String,
    pub(super) sequence: u64,
    pub(super) fingerprint: String,
    pub(super) file: RecordFileIdentity,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HistoricalResolutionPermit(PreviousBootFinalizationAuthority);
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PersistedHistoricalResolution(PreviousBootFinalizationAuthority);
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HistoricalRuntimeReleasePermit(PreviousBootFinalizationAuthority);
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HistoricalRuntimeReleaseConfirmed(PreviousBootFinalizationAuthority);
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HistoricalRecordRemovalPermit {
    pub(super) authority: PreviousBootFinalizationAuthority,
    pub(super) file: RecordFileIdentity,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HistoricalRecordRemovedReceipt(PreviousBootFinalizationAuthority);
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HistoricalSeatFreePermit(PreviousBootFinalizationAuthority);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PreviousBootFinalizationOutcome {
    SeatFreed,
    PreservedQuarantine,
}

#[derive(Debug)]
pub(crate) enum PreviousBootFinalizationError {
    PlanChanged,
    StaleSnapshot,
    Conflicted,
    DurableConflict(HistoricalDurableStateConflict),
    Io(io::Error),
}

impl fmt::Display for PreviousBootFinalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanChanged => formatter.write_str("previous-boot plan changed"),
            Self::StaleSnapshot => formatter.write_str("previous-boot snapshot is stale"),
            Self::Conflicted => formatter.write_str("previous-boot finalization is conflicted"),
            Self::DurableConflict(conflict) => {
                write!(formatter, "durable previous-boot conflict: {conflict:?}")
            }
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl From<io::Error> for PreviousBootFinalizationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<HistoricalDurableStateConflict> for PreviousBootFinalizationError {
    fn from(conflict: HistoricalDurableStateConflict) -> Self {
        Self::DurableConflict(conflict)
    }
}

#[path = "previous_boot_finalization_tail.rs"]
mod tail;
pub(crate) use tail::execute_previous_boot_plan;

#[path = "previous_boot_finalization_resume.rs"]
mod resume;
pub(crate) use resume::resume_removed_previous_boot_finalization;

#[path = "previous_boot_finalization_core.rs"]
mod core;
use core::*;
#[path = "previous_boot_finalization_attempts.rs"]
mod attempts;
use attempts::*;

#[cfg(test)]
#[path = "previous_boot_durability_tests.rs"]
mod durability_tests;
#[cfg(test)]
#[path = "previous_boot_finalization_fixture.rs"]
mod finalization_fixture;
#[cfg(test)]
#[path = "previous_boot_process_tests.rs"]
mod process_tests;
#[cfg(test)]
#[path = "previous_boot_finalization_tests.rs"]
mod tests;
