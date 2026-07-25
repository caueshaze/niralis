use super::recovery::*;
use std::sync::Arc;

/// Complete external-I/O seam for administrative recovery.  Decisions, ledger
/// transitions and seat publication intentionally remain with the coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryAdminBoundaryFacts {
    Absent,
    Populated,
    WorkerAlive,
    LauncherAlive,
    LogindPresent,
    AuthorityChanged,
    AuthorityLost,
    ProcessIdentityReused,
    Indeterminate,
}
impl RecoveryAdminBoundaryFacts {
    pub(crate) const fn is_absent(self) -> bool {
        matches!(self, Self::Absent)
    }
}

pub(crate) trait RecoveryAdminHost: Send + Sync {
    fn inspect_boundary(&self, record: &PersistentRecoveryRecord) -> RecoveryAdminBoundaryFacts;
    /// The host owns construction of the known-process set as it is derived
    /// from procfs.  The coordinator must not read procfs itself.
    fn inspect_vt(
        &self,
        record: &PersistentRecoveryRecord,
        target_vt: u32,
    ) -> crate::VtBusyProvenance;
    fn persisted_vt_identity(
        &self,
        record: &PersistentRecoveryRecord,
    ) -> Result<SupervisorVtIdentity, SupervisorRecoveryError>;
    fn disallocate_vt_once(&self, target_vt: u32) -> Result<(), SupervisorRecoveryError>;
    fn runtime_release(
        &self,
        _record: &PersistentRecoveryRecord,
    ) -> Result<(), SupervisorRecoveryError>;
}

pub(crate) type RecoveryAdminHostRef = Arc<dyn RecoveryAdminHost>;

pub(crate) struct LinuxRecoveryAdminHost;

impl RecoveryAdminHost for LinuxRecoveryAdminHost {
    fn inspect_boundary(&self, record: &PersistentRecoveryRecord) -> RecoveryAdminBoundaryFacts {
        let Ok((systemd, logind)) = open_recovery_owner_watches() else {
            return RecoveryAdminBoundaryFacts::Indeterminate;
        };
        let (Ok(systemd_snapshot), Ok(logind_snapshot)) =
            (systemd.stable_snapshot(), logind.stable_snapshot())
        else {
            return RecoveryAdminBoundaryFacts::AuthorityLost;
        };
        let worker = rehydrate_process_identity(
            record.worker_pid,
            record.worker_starttime,
            record.worker_executable,
            record.worker_cgroup.as_deref(),
        );
        let launcher = rehydrate_process_identity(
            record.launcher_pid,
            record.launcher_starttime,
            record.launcher_executable,
            None,
        );
        match worker {
            PersistedProcessIdentity::OriginalStillAlive { .. } => {
                return RecoveryAdminBoundaryFacts::WorkerAlive
            }
            PersistedProcessIdentity::PidReused => {
                return RecoveryAdminBoundaryFacts::ProcessIdentityReused
            }
            PersistedProcessIdentity::Indeterminate => {
                return RecoveryAdminBoundaryFacts::Indeterminate
            }
            PersistedProcessIdentity::OriginalGone => {}
        }
        match launcher {
            PersistedProcessIdentity::OriginalStillAlive { .. } => {
                return RecoveryAdminBoundaryFacts::LauncherAlive
            }
            PersistedProcessIdentity::PidReused => {
                return RecoveryAdminBoundaryFacts::ProcessIdentityReused
            }
            PersistedProcessIdentity::Indeterminate => {
                return RecoveryAdminBoundaryFacts::Indeterminate
            }
            PersistedProcessIdentity::OriginalGone => {}
        }
        let Some(logind_id) = record
            .logind_session_id
            .as_deref()
            .and_then(|id| crate::LogindSessionId::new(id.to_owned()))
        else {
            return RecoveryAdminBoundaryFacts::Indeterminate;
        };
        match logind_session_exists(logind_id.as_str()) {
            Ok(true) => return RecoveryAdminBoundaryFacts::LogindPresent,
            Ok(false) => {}
            Err(_) => return RecoveryAdminBoundaryFacts::Indeterminate,
        }
        let Some(invocation) = record.invocation_id.as_deref() else {
            return RecoveryAdminBoundaryFacts::Indeterminate;
        };
        let connection = match zbus::blocking::connection::Builder::system().and_then(|builder| {
            builder
                .method_timeout(std::time::Duration::from_secs(2))
                .build()
        }) {
            Ok(connection) => connection,
            Err(_) => return RecoveryAdminBoundaryFacts::Indeterminate,
        };
        match resolve_invocation(&connection, invocation) {
            Ok(Some(_)) => return RecoveryAdminBoundaryFacts::Populated,
            Ok(None) => {}
            Err(_) => return RecoveryAdminBoundaryFacts::Indeterminate,
        }
        if systemd.still_authorizes(&systemd_snapshot).is_err()
            || logind.still_authorizes(&logind_snapshot).is_err()
        {
            return RecoveryAdminBoundaryFacts::AuthorityChanged;
        }
        RecoveryAdminBoundaryFacts::Absent
    }
    fn inspect_vt(
        &self,
        record: &PersistentRecoveryRecord,
        target_vt: u32,
    ) -> crate::VtBusyProvenance {
        inspect_vt_busy(
            target_vt,
            &[
                VtKnownProcess {
                    pid: std::process::id(),
                    starttime: current_process_starttime(),
                },
                VtKnownProcess {
                    pid: record.worker_pid,
                    starttime: record.worker_starttime,
                },
                VtKnownProcess {
                    pid: record.launcher_pid,
                    starttime: record.launcher_starttime,
                },
            ],
        )
    }
    fn persisted_vt_identity(
        &self,
        record: &PersistentRecoveryRecord,
    ) -> Result<SupervisorVtIdentity, SupervisorRecoveryError> {
        persisted_vt_identity(record).map_err(|_| SupervisorRecoveryError::VtIdentityChanged)
    }
    fn disallocate_vt_once(&self, target_vt: u32) -> Result<(), SupervisorRecoveryError> {
        disallocate_virtual_terminal_once(target_vt)
    }
    fn runtime_release(
        &self,
        _record: &PersistentRecoveryRecord,
    ) -> Result<(), SupervisorRecoveryError> {
        Ok(())
    }
}

