use super::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

impl PersistentRecoveryLedger {
    pub(crate) fn clear_seat_startup_quarantine(&mut self, seat: &str) {
        self.startup_quarantined_seats.remove(seat);
    }
    pub(crate) fn historical_journal_path(&self) -> std::path::PathBuf {
        self.directory.join("previous-boot-finalization.journal")
    }
    pub(crate) fn read_historical_journal(&self) -> io::Result<Option<Vec<u8>>> {
        let path = self.historical_journal_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || (metadata.uid() != 0 && !allow_non_root_test_storage())
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe historical finalization journal",
            ));
        }
        match fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn write_historical_journal(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 > MAX_RECOVERY_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "historical journal too large",
            ));
        }
        let tmp = self.directory.join(".previous-boot-finalization.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&tmp)?;
        std::io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(tmp, self.historical_journal_path())?;
        sync_directory(&self.directory)
    }
    pub(crate) fn remove_record_exact(
        &mut self,
        id: &str,
        expected: &crate::launcher::recovery::RecordFileIdentity,
    ) -> io::Result<()> {
        if self.record_file_identity(id)? != *expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recovery record file changed",
            ));
        }
        let record = self
            .records
            .get(id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        if record.state != "record_resolved" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery record is not resolved",
            ));
        }
        fs::remove_file(self.record_path(id)?)?;
        sync_directory(&self.directory)?;
        self.records.remove(id);
        Ok(())
    }
    pub(crate) fn record_file_exists(&self, id: &str) -> io::Result<bool> {
        match self.record_file_identity(id) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

const JOURNAL_VERSION: u32 = 1;
const MAX_JOURNAL_ENTRIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum HistoricalFinalizationStage {
    NotReplayed,
    ResolutionIntent,
    RecordResolved,
    RuntimeReleaseIntent,
    RuntimeReleaseConfirmed,
    RemovalIntent,
    Removed,
    FreePublished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoricalDurableStateConflict {
    CorruptedJournal,
    LedgerAheadOfJournal,
    JournalAheadOfLedger,
    RecordPresentAfterRemovalReceipt,
    RecordMissingBeforeRemoval,
    SequenceConflict,
    ReplacedInode,
    AbandonedTemporaryFile,
    DuplicateJournalCandidate,
    DuplicateRecordEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HistoricalNotReplayed {
    pub(crate) operation: String,
    pub(crate) attempt_id: Option<u64>,
    pub(crate) original_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HistoricalFinalizationEntry {
    pub(crate) record_id: String,
    pub(crate) lifecycle_id: String,
    pub(crate) seat: String,
    pub(crate) boot_id: String,
    pub(crate) sequence: u64,
    pub(crate) stage: HistoricalFinalizationStage,
    pub(crate) not_replayed: Vec<HistoricalNotReplayed>,
    pub(crate) device: Option<u64>,
    pub(crate) inode: Option<u64>,
    pub(crate) links: Option<u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalFinalizationJournal {
    pub(crate) version: u32,
    pub(crate) entries: Vec<HistoricalFinalizationEntry>,
}

impl HistoricalFinalizationJournal {
    pub(crate) fn load(ledger: &PersistentRecoveryLedger) -> io::Result<Self> {
        validate_journal_files(ledger)?;
        let Some(bytes) = ledger.read_historical_journal()? else {
            return Ok(Self {
                version: JOURNAL_VERSION,
                entries: Vec::new(),
            });
        };
        let journal: Self = serde_json::from_slice(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{:?}: {error}",
                    HistoricalDurableStateConflict::CorruptedJournal
                ),
            )
        })?;
        if journal.version != JOURNAL_VERSION || journal.entries.len() > MAX_JOURNAL_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{:?}", HistoricalDurableStateConflict::CorruptedJournal),
            ));
        }
        Ok(journal)
    }

    pub(crate) fn persist(&self, ledger: &PersistentRecoveryLedger) -> io::Result<()> {
        if self.entries.len() > MAX_JOURNAL_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "historical finalization journal is full",
            ));
        }
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        ledger.write_historical_journal(&bytes)
    }

    pub(crate) fn entry(&self, id: &str) -> Option<&HistoricalFinalizationEntry> {
        self.entries.iter().find(|entry| entry.record_id == id)
    }

    pub(crate) fn upsert(&mut self, entry: HistoricalFinalizationEntry) {
        if let Some(current) = self
            .entries
            .iter_mut()
            .find(|current| current.record_id == entry.record_id)
        {
            *current = entry;
        } else {
            self.entries.push(entry);
        }
    }
}

pub(crate) fn historical_not_replayed(
    record: &PersistentRecoveryRecord,
) -> Vec<HistoricalNotReplayed> {
    [
        ("payload_kill", record.operation_ledger.payload_kill),
        ("supervisor_unref", record.operation_ledger.supervisor_unref),
        (
            "logind_termination",
            record.operation_ledger.logind_termination,
        ),
        ("vt_disallocate", record.operation_ledger.vt_disallocate),
    ]
    .into_iter()
    .filter_map(|(operation, state)| match state {
        DurableOperationState::IntentPersisted { attempt_id }
        | DurableOperationState::Indeterminate { attempt_id, .. } => Some(HistoricalNotReplayed {
            operation: operation.to_owned(),
            attempt_id: Some(attempt_id),
            original_state: format!("{state:?}"),
        }),
        DurableOperationState::NotStarted
        | DurableOperationState::Confirmed { .. }
        | DurableOperationState::Failed { .. } => None,
    })
    .collect()
}

#[path = "previous_boot_finalization_validation.rs"]
mod validation;
use validation::validate_journal_files;
