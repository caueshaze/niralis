use super::*;

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
#[derive(Debug)]
pub(crate) struct SupervisorFixtureBoundary {
    pub(crate) identity: crate::PayloadScopeIdentity,
    pub(crate) object_path: String,
    pub(crate) control_group: String,
    pub(crate) slice: String,
    pub(crate) leader_pid: u32,
    pub(crate) mode: SupervisorFixtureBoundaryMode,
    pub(crate) counters: Arc<SupervisorFixtureCounters>,
    pub(crate) payload_members: Arc<Mutex<Vec<u32>>>,
    pub(crate) completion_event: Arc<OwnedFd>,
    pub(crate) released: bool,
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
impl SupervisorPayloadBoundary for SupervisorFixtureBoundary {
    fn identity(&self) -> &crate::PayloadScopeIdentity {
        &self.identity
    }

    fn object_path(&self) -> Option<&str> {
        Some(&self.object_path)
    }

    fn control_group(&self) -> Option<&str> {
        Some(&self.control_group)
    }

    fn slice(&self) -> Option<&str> {
        Some(&self.slice)
    }

    fn leader_pid(&self) -> u32 {
        self.leader_pid
    }

    fn recover_emergency(
        &mut self,
        worker_exit: ExitStatus,
        _timeout: Duration,
    ) -> Result<SupervisorEmergencyBoundaryProof, SupervisorRecoveryError> {
        use std::sync::atomic::Ordering;
        match self.mode {
            SupervisorFixtureBoundaryMode::Replacement => {
                signal_fixture_completion(&self.completion_event);
                return Err(SupervisorRecoveryError::BoundaryIdentityChanged);
            }
            SupervisorFixtureBoundaryMode::BusLoss => {
                signal_fixture_completion(&self.completion_event);
                return Err(SupervisorRecoveryError::BusDeliveryIndeterminate);
            }
            SupervisorFixtureBoundaryMode::Timeout => {
                signal_fixture_completion(&self.completion_event);
                return Err(SupervisorRecoveryError::BoundaryTimedOut);
            }
            SupervisorFixtureBoundaryMode::PopulatedThenRecovered => {
                self.counters.emergency_kills.fetch_add(1, Ordering::SeqCst);
                for pid in self
                    .payload_members
                    .lock()
                    .map_err(|_| SupervisorRecoveryError::InvalidRecord)?
                    .iter()
                    .copied()
                {
                    fixture_pidfd_kill(pid)?;
                }
            }
            SupervisorFixtureBoundaryMode::AlreadyEmpty
            | SupervisorFixtureBoundaryMode::EmptyBoundary
            | SupervisorFixtureBoundaryMode::RestartReconciles
            | SupervisorFixtureBoundaryMode::WorkerAliveHandoff
            | SupervisorFixtureBoundaryMode::PayloadRecovered
            | SupervisorFixtureBoundaryMode::EbusyQuarantine
            | SupervisorFixtureBoundaryMode::UnknownScope
            | SupervisorFixtureBoundaryMode::UnknownScopeKnownSeat
            | SupervisorFixtureBoundaryMode::ScopeRecordConflict
            | SupervisorFixtureBoundaryMode::SystemdOwnerBeforeKill
            | SupervisorFixtureBoundaryMode::SystemdOwnerDuringKill
            | SupervisorFixtureBoundaryMode::SystemdOwnerBeforeProof
            | SupervisorFixtureBoundaryMode::LogindOwnerBeforeTerminate
            | SupervisorFixtureBoundaryMode::LogindOwnerDuringCleanup
            | SupervisorFixtureBoundaryMode::LogindOwnerBeforeAbsence => {}
        }
        self.counters.proofs.fetch_add(1, Ordering::SeqCst);
        Ok(fixture_boundary_proof(&self.identity, worker_exit))
    }

    fn verify_empty(
        &mut self,
        worker_exit: ExitStatus,
    ) -> Result<SupervisorEmergencyBoundaryProof, SupervisorRecoveryError> {
        use std::sync::atomic::Ordering;
        match self.mode {
            SupervisorFixtureBoundaryMode::Replacement => {
                return Err(SupervisorRecoveryError::BoundaryIdentityChanged)
            }
            SupervisorFixtureBoundaryMode::BusLoss => {
                return Err(SupervisorRecoveryError::BusUnavailable)
            }
            SupervisorFixtureBoundaryMode::Timeout
            | SupervisorFixtureBoundaryMode::PopulatedThenRecovered => {
                return Err(SupervisorRecoveryError::BoundaryStillPopulated)
            }
            SupervisorFixtureBoundaryMode::AlreadyEmpty
            | SupervisorFixtureBoundaryMode::EmptyBoundary
            | SupervisorFixtureBoundaryMode::RestartReconciles
            | SupervisorFixtureBoundaryMode::WorkerAliveHandoff
            | SupervisorFixtureBoundaryMode::PayloadRecovered
            | SupervisorFixtureBoundaryMode::EbusyQuarantine
            | SupervisorFixtureBoundaryMode::UnknownScope
            | SupervisorFixtureBoundaryMode::UnknownScopeKnownSeat
            | SupervisorFixtureBoundaryMode::ScopeRecordConflict
            | SupervisorFixtureBoundaryMode::SystemdOwnerBeforeKill
            | SupervisorFixtureBoundaryMode::SystemdOwnerDuringKill
            | SupervisorFixtureBoundaryMode::SystemdOwnerBeforeProof
            | SupervisorFixtureBoundaryMode::LogindOwnerBeforeTerminate
            | SupervisorFixtureBoundaryMode::LogindOwnerDuringCleanup
            | SupervisorFixtureBoundaryMode::LogindOwnerBeforeAbsence => {}
        }
        self.counters.proofs.fetch_add(1, Ordering::SeqCst);
        Ok(fixture_boundary_proof(&self.identity, worker_exit))
    }

    fn release(&mut self) -> Result<(), SupervisorRecoveryError> {
        use std::sync::atomic::Ordering;
        if !self.released {
            self.counters.unrefs.fetch_add(1, Ordering::SeqCst);
            self.released = true;
        }
        Ok(())
    }
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) fn fixture_boundary_proof(
    identity: &crate::PayloadScopeIdentity,
    worker_exit: ExitStatus,
) -> SupervisorEmergencyBoundaryProof {
    SupervisorEmergencyBoundaryProof {
        unit_name: identity.unit_name.clone(),
        invocation_id: identity.invocation_id.clone(),
        control_group: format!(
            "/user.slice/user-{}.slice/{}",
            identity.expected_uid, identity.unit_name
        ),
        worker_exit: exit_status_label(worker_exit),
        leader_observed_dead: true,
        cgroup_observed_empty: true,
    }
}
