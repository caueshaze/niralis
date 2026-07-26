use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[derive(Debug)]
pub(crate) struct PersistentRecoveryLedger {
    pub(crate) directory: std::path::PathBuf,
    _lock: File,
    pub(crate) records: BTreeMap<String, PersistentRecoveryRecord>,
    pub(crate) read_results: Vec<DurableRecoveryRecordReadResult>,
    pub(crate) record_set: RecoveryRecordSetClassification,
    startup_quarantined: bool,
    pub(crate) startup_quarantined_seats: BTreeSet<String>,
}
impl Drop for PersistentRecoveryLedger {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN) };
    }
}
impl PersistentRecoveryLedger {
    pub(crate) fn open(
        directory: impl AsRef<Path>,
        lock_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let directory = directory.as_ref().to_path_buf();
        create_secure_directory(&directory)?;
        if let Some(parent) = lock_path.as_ref().parent() {
            create_lock_parent(parent)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(lock_path)?;
        let lock_metadata = lock.metadata()?;
        if lock_metadata.uid() != 0 && !allow_non_root_test_storage()
            || lock_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "recovery lock permissions",
            ));
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "recovery lock is held",
            ));
        }
        info!(path = %directory.display(), "opening persistent recovery ledger");
        info!("persistent recovery lock acquired");
        let current_boot = current_boot_id()
            .ok()
            .and_then(|value| BootIdentity::parse(value).ok());
        let (records, read_results, startup_quarantined) =
            load_records(&directory, current_boot.as_ref())?;
        let record_set = current_boot
            .as_ref()
            .map(|boot| classify_recovery_record_set(&read_results, boot))
            .unwrap_or_else(|| RecoveryRecordSetClassification {
                global_quarantine: true,
                ..RecoveryRecordSetClassification::default()
            });
        let mut ledger = Self {
            directory,
            _lock: lock,
            records,
            read_results,
            startup_quarantined: startup_quarantined || record_set.global_quarantine,
            record_set,
            startup_quarantined_seats: BTreeSet::new(),
        };
        apply_historical_journal_quarantine(&mut ledger);
        Ok(ledger)
    }
    pub(crate) fn records(&self) -> impl Iterator<Item = &PersistentRecoveryRecord> {
        self.records.values()
    }
    pub(crate) fn read_results(&self) -> &[DurableRecoveryRecordReadResult] {
        &self.read_results
    }
    pub(crate) fn record_set_classification(&self) -> &RecoveryRecordSetClassification {
        &self.record_set
    }
    pub(crate) fn record_file_identity(
        &self,
        id: &str,
    ) -> io::Result<crate::launcher::recovery::RecordFileIdentity> {
        let metadata = fs::symlink_metadata(self.record_path(id)?)?;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsafe recovery record metadata",
            ));
        }
        Ok(crate::launcher::recovery::RecordFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
        })
    }
    pub(crate) fn startup_quarantined(&self) -> bool {
        self.startup_quarantined
    }
    pub(crate) fn mark_startup_quarantine(&mut self) {
        self.startup_quarantined = true;
    }
    pub(crate) fn mark_seat_startup_quarantine(&mut self, seat: impl Into<String>) {
        self.startup_quarantined_seats.insert(seat.into());
    }
    pub(crate) fn seat_startup_quarantined(&self, seat: &str) -> bool {
        self.startup_quarantined_seats.contains(seat)
    }
    pub(crate) fn boot_relation(record: &PersistentRecoveryRecord) -> RecoveryBootRelation {
        match current_boot_id() {
            Ok(current) if current == record.created_boot_id => RecoveryBootRelation::SameBoot,
            _ => RecoveryBootRelation::PreviousBoot,
        }
    }
    pub(crate) fn create(&mut self, record: PersistentRecoveryRecord) -> io::Result<()> {
        if self.records.contains_key(&record.lifecycle_id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "duplicate lifecycle",
            ));
        }
        self.commit(record)
    }
    pub(crate) fn transition(&mut self, id: &str, state: &str) -> io::Result<()> {
        let mut next = self
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        next.transition(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.commit(next)
    }
    pub(crate) fn quarantine(
        &mut self,
        id: &str,
        reason: StartupRecoveryFailure,
    ) -> io::Result<()> {
        let mut next = self
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        next.transition("quarantined")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        next.quarantine_reason = Some(reason.persistent_reason().to_owned());
        self.commit(next)
    }
    pub(crate) fn resolve_and_remove(&mut self, id: &str) -> io::Result<()> {
        self.resolve_state_and_remove(id, "record_resolved")
    }
    /// Persist the resolved lifecycle state without deleting the evidence.
    /// Administrative VT recovery must retain the record through runtime
    /// release so a crash cannot publish a seat as free between those steps.
    pub(crate) fn mark_record_resolved(&mut self, id: &str) -> io::Result<()> {
        let mut next = self
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        next.transition("record_resolved")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.commit(next)
    }
    fn resolve_state_and_remove(&mut self, id: &str, state: &str) -> io::Result<()> {
        let mut next = self
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        next.transition(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.commit(next)?;
        self.remove_resolved(id)
    }
    pub(crate) fn remove_resolved(&mut self, id: &str) -> io::Result<()> {
        let record = self
            .records
            .get(id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        if !matches!(
            record.state.as_str(),
            "record_resolved" | "cleared_by_boot_boundary"
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery record is not resolved",
            ));
        }
        fs::remove_file(self.record_path(id)?)?;
        sync_directory(&self.directory)?;
        self.records.remove(id);
        info!(lifecycle_id = id, "persistent recovery record removed");
        Ok(())
    }
    pub(crate) fn commit(&mut self, record: PersistentRecoveryRecord) -> io::Result<()> {
        // A3.4.3a treats old ledgers as evidence.  Do not migrate a record
        // merely because it was observed during startup.
        validate_record(&record)?;
        let path = self.record_path(&record.lifecycle_id)?;
        let tmp = self.directory.join(format!(".{}.tmp", record.lifecycle_id));
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_RECOVERY_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "record too large",
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &path)?;
        sync_directory(&self.directory)?;
        info!(
            lifecycle_id = %record.lifecycle_id,
            sequence = record.sequence,
            state = %record.state,
            "durable recovery transition committed"
        );
        self.records.insert(record.lifecycle_id.clone(), record);
        Ok(())
    }
    pub(crate) fn record_path(&self, id: &str) -> io::Result<std::path::PathBuf> {
        validate_lifecycle_id(id)?;
        Ok(self.directory.join(format!("{id}.json")))
    }
}

#[path = "persistent_storage_journal.rs"]
mod journal;
use journal::apply_historical_journal_quarantine;
