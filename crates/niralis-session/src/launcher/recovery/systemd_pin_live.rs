use super::*;

impl LivePinnedInvocationUnit {
    pub(crate) fn acquire(
        identity: crate::PayloadScopeIdentity,
        leader_pid: u32,
        worker_pid: u32,
        launcher_pid: u32,
        leader: &SupervisorLeaderPidfd,
    ) -> Result<Self, SupervisorRecoveryError> {
        let binding = LiveLifecycleBinding {
            identity: identity.clone(),
        };
        Ok(Self {
            inner: PinnedInvocationInner::acquire(
                identity,
                leader_pid,
                worker_pid,
                launcher_pid,
                leader,
            )?,
            live_binding: binding,
        })
    }

    pub(crate) fn identity(&self) -> &crate::PayloadScopeIdentity {
        &self.live_binding.identity
    }
    pub(crate) fn object_path(&self) -> &str {
        &self.inner.object_path
    }
    pub(crate) fn control_group(&self) -> &str {
        &self.inner.control_group
    }
    pub(crate) fn slice(&self) -> &str {
        &self.inner.slice
    }
    pub(crate) fn worker_pid(&self) -> u32 {
        self.inner.worker_pid
    }
    pub(crate) fn launcher_pid(&self) -> u32 {
        self.inner.launcher_pid
    }
    pub(crate) fn connection(&self) -> &zbus::blocking::Connection {
        &self.inner.connection
    }
    pub(crate) fn revalidate(
        &self,
        terminal: bool,
    ) -> Result<SupervisorUnitObservation, SupervisorRecoveryError> {
        self.inner.revalidate(terminal)
    }
    pub(crate) fn validate_owner(&self) -> Result<(), SupervisorRecoveryError> {
        self.inner.validate_owner()
    }
    pub(crate) fn boundary_state(
        &self,
    ) -> Result<SupervisorBoundaryState, SupervisorRecoveryError> {
        self.inner.boundary_state()
    }
    pub(crate) fn request_live_emergency_kill(&mut self) -> Result<(), SupervisorRecoveryError> {
        self.inner.request_emergency_kill()
    }
    pub(crate) fn release_live(&mut self) -> Result<(), SupervisorRecoveryError> {
        self.inner.release()
    }
}
