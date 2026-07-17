pub struct GracefulTerminationCoordinator {
    cause: Option<TerminationCause>,
    leader_exit: Option<LeaderExit>,
    timer: GraceTimerFd,
    requested: bool,
    finished: bool,
}

impl GracefulTerminationCoordinator {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            cause: None,
            leader_exit: None,
            timer: GraceTimerFd::new()?,
            requested: false,
            finished: false,
        })
    }
    pub fn timer_fd(&self) -> RawFd {
        self.timer.as_raw_fd()
    }
    pub fn cause(&self) -> Option<&TerminationCause> {
        self.cause.as_ref()
    }
    pub fn record_leader_exit(&mut self, exit: LeaderExit) {
        if self.leader_exit.is_none() {
            self.leader_exit = Some(exit);
        }
    }
    pub fn begin(
        &mut self,
        cause: TerminationCause,
        duration: Duration,
        scope: &dyn crate::payload_scope::AuthoritativePayloadScope,
    ) -> Result<
        Option<Box<dyn crate::payload_scope::PayloadBoundaryObserver>>,
        GracefulTerminationOutcome,
    > {
        if self.requested {
            return Ok(None);
        }
        self.cause = Some(cause);
        let observer = scope
            .create_boundary_observer()
            .map_err(|error| self.scope_error(error))?;
        scope
            .request_graceful_termination()
            .map_err(|error| self.scope_error(error))?;
        self.timer
            .arm_once(duration)
            .map_err(|_| self.infrastructure(GracefulTerminationError::Timer))?;
        self.requested = true;
        Ok(Some(observer))
    }
    pub fn boundary_candidate(
        &mut self,
        observation: BoundaryTerminalObservation,
    ) -> GracefulTerminationOutcome {
        self.finished = true;
        GracefulTerminationOutcome::BoundaryTerminalCandidate {
            cause: self
                .cause
                .clone()
                .unwrap_or(TerminationCause::RuntimeFailure),
            leader_exit: self.leader_exit.clone(),
            observation,
        }
    }
    pub fn deadline_expired(&mut self) -> GracefulTerminationOutcome {
        self.finished = true;
        GracefulTerminationOutcome::DeadlineExpired {
            cause: self
                .cause
                .clone()
                .unwrap_or(TerminationCause::RuntimeFailure),
            leader_exit: self.leader_exit.clone(),
        }
    }
    pub fn infrastructure(
        &mut self,
        error: GracefulTerminationError,
    ) -> GracefulTerminationOutcome {
        self.finished = true;
        GracefulTerminationOutcome::InfrastructureFailure {
            cause: self
                .cause
                .clone()
                .unwrap_or(TerminationCause::RuntimeFailure),
            leader_exit: self.leader_exit.clone(),
            error,
        }
    }
    pub fn scope_error(
        &mut self,
        error: crate::payload_scope::PayloadScopeError,
    ) -> GracefulTerminationOutcome {
        if error == crate::payload_scope::PayloadScopeError::UnitReplaced {
            self.finished = true;
            GracefulTerminationOutcome::RecoveryRequired {
                cause: self
                    .cause
                    .clone()
                    .unwrap_or(TerminationCause::RuntimeFailure),
                leader_exit: self.leader_exit.clone(),
                reason: RecoveryReason::BoundaryIdentityChanged,
            }
        } else {
            self.infrastructure(GracefulTerminationError::ScopeOperation(error))
        }
    }
    pub fn consume_deadline(&self) -> io::Result<bool> {
        self.timer.consume()
    }
}

