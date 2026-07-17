pub struct ForcedTerminationCoordinator {
    cause: TerminationCause,
    leader_exit: Option<LeaderExit>,
    timer: GraceTimerFd,
    kill_attempted: bool,
    finished: bool,
}

impl ForcedTerminationCoordinator {
    pub fn new(
        cause: TerminationCause,
        leader_exit: Option<LeaderExit>,
    ) -> io::Result<Self> {
        Ok(Self {
            cause,
            leader_exit,
            timer: GraceTimerFd::new()?,
            kill_attempted: false,
            finished: false,
        })
    }

    pub fn timer_fd(&self) -> RawFd {
        self.timer.as_raw_fd()
    }

    pub fn leader_exit(&self) -> Option<&LeaderExit> {
        self.leader_exit.as_ref()
    }

    pub fn record_leader_exit(&mut self, exit: LeaderExit) {
        if self.leader_exit.is_none() {
            self.leader_exit = Some(exit);
        }
    }

    pub fn begin(
        &mut self,
        duration: Duration,
        scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
    ) -> Result<Box<dyn crate::payload_scope::PayloadBoundaryObserver>, ForcedTerminationOutcome>
    {
        if self.kill_attempted {
            return Err(self.infrastructure(
                ForcedTerminationStage::Kill,
                ForcedTerminationError::ScopeOperation(
                    crate::payload_scope::PayloadScopeError::InvalidIdentity,
                ),
            ));
        }
        scope
            .validate_forced_termination_eligibility()
            .map_err(|error| self.scope_error(ForcedTerminationStage::PreKillValidation, error))?;
        let observer = scope
            .create_boundary_observer()
            .map_err(|error| self.scope_error(ForcedTerminationStage::BoundaryObservation, error))?;

        // The attempt bit is set before crossing D-Bus. An indeterminate reply
        // must never turn into an automatic second SIGKILL request.
        self.kill_attempted = true;
        scope
            .request_forced_termination()
            .map_err(|error| self.scope_error(ForcedTerminationStage::Kill, error))?;
        scope
            .validate_forced_termination_post_kill()
            .map_err(|error| {
                self.scope_error(ForcedTerminationStage::PostKillValidation, error)
            })?;
        self.timer.arm_once(duration).map_err(|_| {
            self.infrastructure(ForcedTerminationStage::Kill, ForcedTerminationError::Timer)
        })?;
        Ok(observer)
    }

    pub fn boundary_empty(&mut self, proof: BoundaryEmptyProof) -> ForcedTerminationOutcome {
        self.finished = true;
        let leader_exit = proof.leader_exit().clone();
        ForcedTerminationOutcome::BoundaryEmpty { proof, leader_exit }
    }

    pub fn deadline_expired(&mut self) -> ForcedTerminationOutcome {
        self.finished = true;
        ForcedTerminationOutcome::ForcedDeadlineExpired {
            cause: self.cause.clone(),
            leader_exit: self.leader_exit.clone(),
        }
    }

    pub fn infrastructure(
        &mut self,
        stage: ForcedTerminationStage,
        error: ForcedTerminationError,
    ) -> ForcedTerminationOutcome {
        self.finished = true;
        ForcedTerminationOutcome::InfrastructureFailure {
            cause: self.cause.clone(),
            leader_exit: self.leader_exit.clone(),
            stage,
            error,
        }
    }

    pub fn scope_error(
        &mut self,
        stage: ForcedTerminationStage,
        error: crate::payload_scope::PayloadScopeError,
    ) -> ForcedTerminationOutcome {
        if error == crate::payload_scope::PayloadScopeError::UnitReplaced {
            self.finished = true;
            ForcedTerminationOutcome::RecoveryRequired {
                cause: self.cause.clone(),
                leader_exit: self.leader_exit.clone(),
                reason: RecoveryReason::BoundaryIdentityChanged,
            }
        } else if matches!(
            error,
            crate::payload_scope::PayloadScopeError::WorkerInsideBoundary
                | crate::payload_scope::PayloadScopeError::InvalidIdentity
                | crate::payload_scope::PayloadScopeError::CgroupMismatch
                | crate::payload_scope::PayloadScopeError::InvalidMembership
        ) {
            self.finished = true;
            ForcedTerminationOutcome::RecoveryRequired {
                cause: self.cause.clone(),
                leader_exit: self.leader_exit.clone(),
                reason: RecoveryReason::BoundaryIdentityUnproven,
            }
        } else {
            self.infrastructure(stage, ForcedTerminationError::ScopeOperation(error))
        }
    }

    pub fn consume_deadline(&self) -> io::Result<bool> {
        self.timer.consume()
    }
}
