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

#[cfg(all(feature = "supervisor-test-fixtures", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlledRecoveryAdminEvent {
    Boundary,
    InspectVt,
    PersistedVtIdentity,
    DisallocateVtOnce,
    RuntimeRelease,
}

#[cfg(all(feature = "supervisor-test-fixtures", test))]
pub(crate) struct ControlledRecoveryAdminHost {
    pub(crate) boundary: RecoveryAdminBoundaryFacts,
    pub(crate) vt: SupervisorVtIdentity,
    pub(crate) before: crate::VtBusyProvenance,
    pub(crate) after: crate::VtBusyProvenance,
    pub(crate) disallocate: Result<(), SupervisorRecoveryError>,
    pub(crate) runtime: Result<(), SupervisorRecoveryError>,
    pub(crate) events: std::sync::Mutex<Vec<ControlledRecoveryAdminEvent>>,
}

#[cfg(all(feature = "supervisor-test-fixtures", test))]
impl ControlledRecoveryAdminHost {
    pub(crate) fn events(&self) -> Vec<ControlledRecoveryAdminEvent> {
        self.events.lock().expect("fixture events").clone()
    }
    fn event(&self, event: ControlledRecoveryAdminEvent) {
        let mut events = self.events.lock().expect("fixture events");
        assert!(events.len() < 64, "bounded fixture recorder");
        events.push(event);
    }
}

#[cfg(all(feature = "supervisor-test-fixtures", test))]
impl RecoveryAdminHost for ControlledRecoveryAdminHost {
    fn inspect_boundary(&self, _: &PersistentRecoveryRecord) -> RecoveryAdminBoundaryFacts {
        self.event(ControlledRecoveryAdminEvent::Boundary);
        self.boundary
    }
    fn inspect_vt(&self, _: &PersistentRecoveryRecord, _: u32) -> crate::VtBusyProvenance {
        self.event(ControlledRecoveryAdminEvent::InspectVt);
        if self
            .events()
            .iter()
            .filter(|event| matches!(event, ControlledRecoveryAdminEvent::InspectVt))
            .count()
            > 1
        {
            self.after.clone()
        } else {
            self.before.clone()
        }
    }
    fn persisted_vt_identity(
        &self,
        _: &PersistentRecoveryRecord,
    ) -> Result<SupervisorVtIdentity, SupervisorRecoveryError> {
        self.event(ControlledRecoveryAdminEvent::PersistedVtIdentity);
        Ok(self.vt.clone())
    }
    fn disallocate_vt_once(&self, _: u32) -> Result<(), SupervisorRecoveryError> {
        self.event(ControlledRecoveryAdminEvent::DisallocateVtOnce);
        self.disallocate.clone()
    }
    fn runtime_release(&self, _: &PersistentRecoveryRecord) -> Result<(), SupervisorRecoveryError> {
        self.event(ControlledRecoveryAdminEvent::RuntimeRelease);
        self.runtime.clone()
    }
}

fn current_process_starttime() -> Option<u64> {
    std::fs::read_to_string("/proc/self/stat")
        .ok()?
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(all(test, feature = "supervisor-test-fixtures"))]
mod tests {
    use super::*;
    #[test]
    fn controlled_host_never_falls_back_to_linux() {
        let provenance = crate::VtBusyProvenance {
            target_vt: 2,
            observed_active_vt: Some(7),
            target_is_foreground: Some(false),
            target_device: None,
            visible_holders: Vec::new(),
            holders_truncated: false,
            inspection_failures: Vec::new(),
            classification: crate::VtBusyClassification::KernelBusyUnattributed,
            captured_at_boottime_ns: 1,
        };
        let host = ControlledRecoveryAdminHost {
            boundary: RecoveryAdminBoundaryFacts::Absent,
            vt: SupervisorVtIdentity {
                seat: "seat0".into(),
                number: 2,
                previous: PreviousVtIdentity { number: 7 },
                device_major: 4,
                device_minor: 2,
            },
            before: provenance.clone(),
            after: provenance,
            disallocate: Err(SupervisorRecoveryError::VtDisallocateBusy),
            runtime: Ok(()),
            events: std::sync::Mutex::new(Vec::new()),
        };
        assert!(matches!(
            host.disallocate_vt_once(2),
            Err(SupervisorRecoveryError::VtDisallocateBusy)
        ));
        assert_eq!(
            host.events(),
            vec![ControlledRecoveryAdminEvent::DisallocateVtOnce]
        );
    }
}
