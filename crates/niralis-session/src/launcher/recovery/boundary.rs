use super::*;

pub(crate) trait SupervisorPayloadBoundary: Send + fmt::Debug {
    fn identity(&self) -> &crate::PayloadScopeIdentity;
    fn object_path(&self) -> Option<&str> {
        None
    }
    fn control_group(&self) -> Option<&str> {
        None
    }
    fn slice(&self) -> Option<&str> {
        None
    }
    fn leader_pid(&self) -> u32;
    fn recover_emergency(
        &mut self,
        worker_exit: ExitStatus,
        timeout: Duration,
    ) -> Result<SupervisorEmergencyBoundaryProof, SupervisorRecoveryError>;
    fn verify_empty(
        &mut self,
        worker_exit: ExitStatus,
    ) -> Result<SupervisorEmergencyBoundaryProof, SupervisorRecoveryError>;
    fn release(&mut self) -> Result<(), SupervisorRecoveryError>;
}
#[derive(Debug)]
pub(crate) struct LinuxSupervisorPayloadBoundary {
    pub(crate) pin: SupervisorPinnedInvocationUnit,
    pub(crate) leader: SupervisorLeaderPidfd,
}

impl SupervisorPayloadBoundary for LinuxSupervisorPayloadBoundary {
    fn identity(&self) -> &crate::PayloadScopeIdentity {
        &self.pin.identity
    }

    fn leader_pid(&self) -> u32 {
        self.leader.pid
    }

    fn object_path(&self) -> Option<&str> {
        Some(&self.pin.object_path)
    }
    fn control_group(&self) -> Option<&str> {
        Some(&self.pin.control_group)
    }
    fn slice(&self) -> Option<&str> {
        Some(&self.pin.slice)
    }

    fn recover_emergency(
        &mut self,
        worker_exit: ExitStatus,
        timeout: Duration,
    ) -> Result<SupervisorEmergencyBoundaryProof, SupervisorRecoveryError> {
        self.pin.revalidate(true)?;
        let initial_state = self.pin.boundary_state()?;
        let mut observer = match initial_state {
            SupervisorBoundaryState::Populated => {
                Some(CgroupEventsObserver::open(&self.pin.control_group)?)
            }
            SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent => None,
        };
        if matches!(initial_state, SupervisorBoundaryState::Populated) {
            self.pin.request_emergency_kill()?;
        }
        wait_for_emergency_boundary(&self.leader, observer.as_mut(), &self.pin, timeout)?;
        prove_linux_supervisor_emergency_boundary(self, worker_exit)
    }

    fn verify_empty(
        &mut self,
        worker_exit: ExitStatus,
    ) -> Result<SupervisorEmergencyBoundaryProof, SupervisorRecoveryError> {
        prove_linux_supervisor_emergency_boundary(self, worker_exit)
    }

    fn release(&mut self) -> Result<(), SupervisorRecoveryError> {
        self.pin.release()
    }
}

pub(crate) struct SupervisorPreparedPayload {
    pub(crate) boundary: Box<dyn SupervisorPayloadBoundary>,
    pub(crate) logind: SupervisorLogindSessionIdentity,
    pub(crate) vt: SupervisorVtIdentity,
    pub(crate) target_gid: u32,
}

impl fmt::Debug for SupervisorPreparedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisorPreparedPayload")
            .field("boundary", &self.boundary)
            .field("logind", &self.logind)
            .field("vt", &self.vt)
            .field("target_gid", &self.target_gid)
            .finish()
    }
}
