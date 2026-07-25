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

