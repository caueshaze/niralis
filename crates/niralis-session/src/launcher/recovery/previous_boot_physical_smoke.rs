use super::*;
use std::io;
use std::path::{Path, PathBuf};

const SMOKE_ROOT: &str = "/var/lib/niralis-smoke";
const CONTROL_FILE: &str = "failpoint.env";
const RECORD_PREFIX: &str = "previous-boot-smoke-";

#[path = "previous_boot_physical_smoke_control.rs"]
mod previous_boot_physical_smoke_control;
#[path = "previous_boot_physical_smoke_controller.rs"]
mod previous_boot_physical_smoke_controller;
#[path = "previous_boot_physical_smoke_storage.rs"]
mod previous_boot_physical_smoke_storage;

#[cfg(test)]
#[path = "previous_boot_physical_smoke_tests.rs"]
mod tests;

/// Root-owned paths for one physical PreviousBoot smoke run.
///
/// This type is compiled only in fixture builds. Production code has no way to
/// select these paths or to create a smoke record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalPreviousBootSmokePaths {
    run_id: String,
    root: PathBuf,
    recovery_dir: PathBuf,
    recovery_lock: PathBuf,
    control_file: PathBuf,
}

impl PhysicalPreviousBootSmokePaths {
    pub fn for_run_id(run_id: &str) -> io::Result<Self> {
        previous_boot_physical_smoke_storage::validate_run_id(run_id)?;
        Self::under_root(PathBuf::from(SMOKE_ROOT), run_id)
    }

    fn under_root(root: PathBuf, run_id: &str) -> io::Result<Self> {
        previous_boot_physical_smoke_storage::validate_run_id(run_id)?;
        let root = root.join(run_id);
        Ok(Self {
            run_id: run_id.to_owned(),
            recovery_dir: root.join("recovery"),
            recovery_lock: root.join("recovery.lock"),
            control_file: root.join(CONTROL_FILE),
            root,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn recovery_dir(&self) -> &Path {
        &self.recovery_dir
    }

    pub fn recovery_lock(&self) -> &Path {
        &self.recovery_lock
    }

    pub fn control_file(&self) -> &Path {
        &self.control_file
    }

    fn record_id(&self) -> String {
        format!("{RECORD_PREFIX}{}", self.run_id)
    }
}

/// The two physical reboot boundaries required by A3.4.3c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalPreviousBootSmokeFailpoint {
    AfterHistoricalResolved,
    AfterRuntimeReleaseConfirmed,
}

impl PhysicalPreviousBootSmokeFailpoint {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "after_historical_resolved" => Ok(Self::AfterHistoricalResolved),
            "after_runtime_release_confirmed" => Ok(Self::AfterRuntimeReleaseConfirmed),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported physical PreviousBoot smoke failpoint",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AfterHistoricalResolved => "after_historical_resolved",
            Self::AfterRuntimeReleaseConfirmed => "after_runtime_release_confirmed",
        }
    }

    fn expected_stage(self) -> HistoricalFinalizationStage {
        match self {
            Self::AfterHistoricalResolved => HistoricalFinalizationStage::RecordResolved,
            Self::AfterRuntimeReleaseConfirmed => {
                HistoricalFinalizationStage::RuntimeReleaseConfirmed
            }
        }
    }
}

/// Fixture-only controller for a physical PreviousBoot smoke run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalPreviousBootSmoke {
    paths: PhysicalPreviousBootSmokePaths,
}
