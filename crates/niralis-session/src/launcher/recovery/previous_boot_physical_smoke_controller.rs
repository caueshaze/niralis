use super::previous_boot_physical_smoke_control::{
    clear_control_file, read_optional_control_file, read_required_control_file, write_control_file,
};
use super::previous_boot_physical_smoke_storage::{
    ensure_secure_root, only_smoke_record, physical_boot_id, reject_test_boot_override, seed_record,
};
use super::*;

impl PhysicalPreviousBootSmoke {
    pub fn new(paths: PhysicalPreviousBootSmokePaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &PhysicalPreviousBootSmokePaths {
        &self.paths
    }

    pub fn armed_failpoint(&self) -> io::Result<Option<PhysicalPreviousBootSmokeFailpoint>> {
        reject_test_boot_override()?;
        ensure_secure_root(self.paths.root())?;
        read_optional_control_file(self.paths.control_file())
    }

    /// Persists one SameBoot record that can become PreviousBoot only after a
    /// real reboot. The seeded operations are deliberately non-replayable.
    pub fn seed(&self) -> io::Result<()> {
        reject_test_boot_override()?;
        ensure_secure_root(self.paths.root())?;
        let current_boot = physical_boot_id()?;
        let mut ledger =
            PersistentRecoveryLedger::open(self.paths.recovery_dir(), self.paths.recovery_lock())?;
        if ledger.records().next().is_some()
            || !ledger.read_results().is_empty()
            || ledger.historical_journal_path().exists()
            || self.paths.control_file().exists()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "physical PreviousBoot smoke run is not empty",
            ));
        }
        ledger.create(seed_record(&self.paths, current_boot))?;
        tracing::info!(
            run_id = %self.paths.run_id(),
            recovery_dir = %self.paths.recovery_dir().display(),
            "previous_boot_physical_smoke_seeded"
        );
        Ok(())
    }

    pub fn arm(&self, failpoint: PhysicalPreviousBootSmokeFailpoint) -> io::Result<()> {
        reject_test_boot_override()?;
        self.assert_seed_is_same_boot()?;
        write_control_file(self.paths.control_file(), failpoint.as_str())?;
        tracing::info!(run_id = %self.paths.run_id(), stage = failpoint.as_str(), "previous_boot_physical_smoke_armed");
        Ok(())
    }

    pub fn disarm(&self) -> io::Result<()> {
        reject_test_boot_override()?;
        let failpoint = read_required_control_file(self.paths.control_file())?;
        let ledger =
            PersistentRecoveryLedger::open(self.paths.recovery_dir(), self.paths.recovery_lock())?;
        let record_id = self.paths.record_id();
        if !ledger
            .records()
            .any(|record| record.lifecycle_id == record_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "physical PreviousBoot smoke record disappeared before disarm",
            ));
        }
        let journal = HistoricalFinalizationJournal::load(&ledger)?;
        let Some(entry) = journal.entry(&record_id) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "physical PreviousBoot smoke journal entry is missing",
            ));
        };
        if entry.stage != failpoint.expected_stage() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "physical PreviousBoot smoke did not reach its armed durable stage",
            ));
        }
        clear_control_file(self.paths.control_file())?;
        tracing::info!(run_id = %self.paths.run_id(), stage = failpoint.as_str(), "previous_boot_physical_smoke_disarmed");
        Ok(())
    }

    /// Rejects a SameBoot invocation before the normal launcher is created.
    /// This keeps SameBoot effectful adapters unreachable from this harness.
    pub fn assert_previous_boot_ready(&self) -> io::Result<()> {
        reject_test_boot_override()?;
        self.assert_previous_boot_ready_against(&physical_boot_id()?)
    }

    fn assert_seed_is_same_boot(&self) -> io::Result<()> {
        ensure_secure_root(self.paths.root())?;
        let current_boot = physical_boot_id()?;
        let ledger =
            PersistentRecoveryLedger::open(self.paths.recovery_dir(), self.paths.recovery_lock())?;
        let record = only_smoke_record(&ledger, &self.paths)?;
        if record.created_boot_id != current_boot {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "physical PreviousBoot smoke seed must be armed before reboot",
            ));
        }
        Ok(())
    }

    pub(super) fn assert_previous_boot_ready_against(&self, current_boot: &str) -> io::Result<()> {
        ensure_secure_root(self.paths.root())?;
        let ledger =
            PersistentRecoveryLedger::open(self.paths.recovery_dir(), self.paths.recovery_lock())?;
        let record = only_smoke_record(&ledger, &self.paths)?;
        if record.created_boot_id == current_boot {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "physical PreviousBoot smoke record is still SameBoot",
            ));
        }
        if ledger.record_set_classification().global_quarantine {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "physical PreviousBoot smoke ledger is globally quarantined",
            ));
        }
        tracing::info!(
            run_id = %self.paths.run_id(),
            recorded_boot = %record.created_boot_id,
            current_boot,
            "previous_boot_physical_smoke_preflight_passed"
        );
        Ok(())
    }
}
