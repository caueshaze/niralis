use super::*;

/// The only capability that can move a seat from `Free` into a pre-commit
/// lifecycle.  It is deliberately neither `Clone` nor `Copy`.
#[derive(Debug)]
pub(in crate::launcher) struct AdmissionLease {
    seat: String,
    attempt_id: u64,
    lifecycle_id: String,
    generation: u64,
    previous_vt: PreviousVtIdentity,
}

#[derive(Debug)]
pub(in crate::launcher) struct PendingLifecycleLease {
    seat: String,
    attempt_id: u64,
    lifecycle_id: String,
    generation: u64,
}

#[derive(Debug)]
pub(in crate::launcher) struct LaunchCommitReceipt {
    seat: String,
    attempt_id: u64,
    lifecycle_id: String,
    generation: u64,
}

#[derive(Debug)]
pub(in crate::launcher) struct RunningSeatReceipt {
    seat: String,
    lifecycle_id: String,
    generation: u64,
}

#[derive(Debug)]
pub(in crate::launcher) struct RecoverySeatReceipt {
    seat: String,
    lifecycle_id: String,
    generation: u64,
}

/// A3-only capability proving that the durable recovery chain removed exactly
/// one record and may now publish the corresponding seat as free.
#[derive(Debug)]
pub(in crate::launcher) struct AdminFinalizationReceipt {
    seat: String,
    lifecycle_id: String,
    seat_generation: u64,
    recovery_record_id: String,
    finalization_sequence: u64,
}

#[derive(Debug)]
pub(in crate::launcher) enum AdmissionRollbackLease {
    Reserved(AdmissionLease),
    Pending(PendingLifecycleLease),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::launcher) enum RecoveryAdmissionState {
    Clear,
    SeatBlocked { seat: String, reason: &'static str },
    GloballyBlocked { reason: &'static str },
}

#[derive(Debug)]
enum AdmissionPhase {
    Free,
    Reserved {
        attempt_id: u64,
        lifecycle_id: String,
        generation: u64,
    },
    PendingLifecycle {
        attempt_id: u64,
        lifecycle_id: String,
        generation: u64,
    },
    LaunchCommitted {
        attempt_id: u64,
        lifecycle_id: String,
        generation: u64,
    },
}

#[derive(Debug)]
pub(in crate::launcher) struct SeatAdmissionController {
    seat: String,
    lifecycle: SeatLifecycle,
    generation: u64,
    next_attempt_id: u64,
    phase: AdmissionPhase,
}

impl SeatAdmissionController {
    pub(in crate::launcher) fn new(seat: impl Into<String>, lifecycle: SeatLifecycle) -> Self {
        let generation = if matches!(&lifecycle, SeatLifecycle::Free) {
            0
        } else {
            1
        };
        Self {
            seat: seat.into(),
            lifecycle,
            generation,
            next_attempt_id: 1,
            phase: AdmissionPhase::Free,
        }
    }

    pub(in crate::launcher) fn reserve(
        &mut self,
        lifecycle_id: String,
        recovery: RecoveryAdmissionState,
        previous_vt: PreviousVtIdentity,
    ) -> Result<AdmissionLease, SessionError> {
        if lifecycle_id.is_empty()
            || !matches!(recovery, RecoveryAdmissionState::Clear)
            || !matches!(self.phase, AdmissionPhase::Free)
            || !matches!(self.lifecycle, SeatLifecycle::Free)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        let attempt_id = self.next_attempt_id;
        self.next_attempt_id = self.next_attempt_id.wrapping_add(1).max(1);
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.phase = AdmissionPhase::Reserved {
            attempt_id,
            lifecycle_id: lifecycle_id.clone(),
            generation,
        };
        Ok(AdmissionLease {
            seat: self.seat.clone(),
            attempt_id,
            lifecycle_id,
            generation,
            previous_vt,
        })
    }

    pub(in crate::launcher) fn promote(
        &mut self,
        lease: AdmissionLease,
        recovery: RecoveryAdmissionState,
    ) -> Result<(PendingLifecycleLease, PreviousVtIdentity), (SessionError, AdmissionLease)> {
        if !matches!(recovery, RecoveryAdmissionState::Clear) || !self.matches_reserved(&lease) {
            return Err((SessionError::SessionSeatUnavailable, lease));
        }
        self.phase = AdmissionPhase::PendingLifecycle {
            attempt_id: lease.attempt_id,
            lifecycle_id: lease.lifecycle_id.clone(),
            generation: lease.generation,
        };
        let pending = PendingLifecycleLease {
            seat: lease.seat.clone(),
            attempt_id: lease.attempt_id,
            lifecycle_id: lease.lifecycle_id.clone(),
            generation: lease.generation,
        };
        Ok((pending, lease.previous_vt))
    }

    pub(in crate::launcher) fn commit(
        &mut self,
        lease: PendingLifecycleLease,
        recovery: RecoveryAdmissionState,
    ) -> Result<LaunchCommitReceipt, (SessionError, PendingLifecycleLease)> {
        if !matches!(recovery, RecoveryAdmissionState::Clear) || !self.matches_pending(&lease) {
            return Err((SessionError::SessionSeatUnavailable, lease));
        }
        self.phase = AdmissionPhase::LaunchCommitted {
            attempt_id: lease.attempt_id,
            lifecycle_id: lease.lifecycle_id.clone(),
            generation: lease.generation,
        };
        Ok(LaunchCommitReceipt {
            seat: lease.seat,
            attempt_id: lease.attempt_id,
            lifecycle_id: lease.lifecycle_id,
            generation: lease.generation,
        })
    }

    pub(super) fn promote_committed_to_running(
        &mut self,
        receipt: LaunchCommitReceipt,
    ) -> Result<RunningSeatReceipt, SessionError> {
        let AdmissionPhase::LaunchCommitted {
            attempt_id,
            lifecycle_id,
            generation,
        } = &self.phase
        else {
            return Err(SessionError::WorkerProtocolFailed);
        };
        if receipt.seat != self.seat
            || receipt.attempt_id != *attempt_id
            || receipt.lifecycle_id != *lifecycle_id
            || receipt.generation != *generation
            || receipt.generation != self.generation
        {
            return Err(SessionError::WorkerProtocolFailed);
        }
        self.phase = AdmissionPhase::Free;
        self.lifecycle = SeatLifecycle::Active {
            lifecycle_id: receipt.lifecycle_id.clone(),
        };
        Ok(RunningSeatReceipt {
            seat: receipt.seat,
            lifecycle_id: receipt.lifecycle_id,
            generation: receipt.generation,
        })
    }

    pub(super) fn enter_recovery(
        &mut self,
        receipt: RunningSeatReceipt,
        phase: &'static str,
        reason: WorkerExitClassification,
    ) -> Result<RecoverySeatReceipt, SessionError> {
        if receipt.seat != self.seat
            || receipt.generation != self.generation
            || !matches!(&self.lifecycle, SeatLifecycle::Active { lifecycle_id } if lifecycle_id == &receipt.lifecycle_id)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.lifecycle = SeatLifecycle::Recovering {
            lifecycle_id: receipt.lifecycle_id.clone(),
            phase,
            reason,
        };
        Ok(RecoverySeatReceipt {
            seat: receipt.seat,
            lifecycle_id: receipt.lifecycle_id,
            generation: receipt.generation,
        })
    }

    pub(super) fn enter_quarantine_from_pending(
        &mut self,
        receipt: PendingLifecycleLease,
        stage: EmergencyRecoveryStage,
        reason: SupervisorRecoveryError,
    ) -> Result<(), SessionError> {
        if !self.matches_pending(&receipt) {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.phase = AdmissionPhase::Free;
        self.lifecycle = SeatLifecycle::Quarantined {
            lifecycle_id: receipt.lifecycle_id,
            stage,
            reason,
        };
        Ok(())
    }

    pub(super) fn quarantine_pending_lifecycle(
        &mut self,
        lifecycle_id: &str,
        stage: EmergencyRecoveryStage,
        reason: SupervisorRecoveryError,
    ) -> Result<(), SessionError> {
        if !matches!(&self.phase, AdmissionPhase::PendingLifecycle { lifecycle_id: current, .. } if current == lifecycle_id)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.phase = AdmissionPhase::Free;
        self.lifecycle = SeatLifecycle::Quarantined {
            lifecycle_id: lifecycle_id.to_owned(),
            stage,
            reason,
        };
        Ok(())
    }

    pub(super) fn enter_quarantine_from_running(
        &mut self,
        receipt: RunningSeatReceipt,
        stage: EmergencyRecoveryStage,
        reason: SupervisorRecoveryError,
    ) -> Result<(), SessionError> {
        if receipt.seat != self.seat
            || receipt.generation != self.generation
            || !matches!(&self.lifecycle, SeatLifecycle::Active { lifecycle_id } if lifecycle_id == &receipt.lifecycle_id)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.lifecycle = SeatLifecycle::Quarantined {
            lifecycle_id: receipt.lifecycle_id,
            stage,
            reason,
        };
        Ok(())
    }

    pub(super) fn enter_quarantine_from_recovery(
        &mut self,
        receipt: RecoverySeatReceipt,
        stage: EmergencyRecoveryStage,
        reason: SupervisorRecoveryError,
    ) -> Result<(), SessionError> {
        if receipt.seat != self.seat
            || receipt.generation != self.generation
            || !matches!(&self.lifecycle, SeatLifecycle::Recovering { lifecycle_id, .. } if lifecycle_id == &receipt.lifecycle_id)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.lifecycle = SeatLifecycle::Quarantined {
            lifecycle_id: receipt.lifecycle_id,
            stage,
            reason,
        };
        Ok(())
    }

    pub(super) fn release_after_a3_finalization(
        &mut self,
        receipt: RecoverySeatReceipt,
    ) -> Result<(), SessionError> {
        if receipt.seat != self.seat
            || receipt.generation != self.generation
            || !matches!(&self.lifecycle, SeatLifecycle::Recovering { lifecycle_id, .. } if lifecycle_id == &receipt.lifecycle_id)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.lifecycle = SeatLifecycle::Free;
        Ok(())
    }

    pub(super) fn release_running_after_a3_finalization(
        &mut self,
        receipt: RunningSeatReceipt,
    ) -> Result<(), SessionError> {
        if receipt.seat != self.seat
            || receipt.generation != self.generation
            || !matches!(&self.lifecycle, SeatLifecycle::Active { lifecycle_id } if lifecycle_id == &receipt.lifecycle_id)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.lifecycle = SeatLifecycle::Free;
        Ok(())
    }

    pub(in crate::launcher) fn is_free(&self) -> bool {
        matches!(self.lifecycle, SeatLifecycle::Free)
    }

    pub(super) fn enter_quarantine_for_admin(
        &mut self,
        lifecycle_id: &str,
    ) -> Result<(), SessionError> {
        if lifecycle_id.is_empty() {
            return Err(SessionError::SessionSeatUnavailable);
        }
        if matches!(&self.lifecycle, SeatLifecycle::Quarantined { lifecycle_id: current, .. } if current == lifecycle_id)
        {
            return Ok(());
        }
        if !self.is_free() || !matches!(self.phase, AdmissionPhase::Free) {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.generation = self.generation.wrapping_add(1).max(1);
        self.lifecycle = SeatLifecycle::Quarantined {
            lifecycle_id: lifecycle_id.to_owned(),
            stage: EmergencyRecoveryStage::VtRecovery,
            reason: SupervisorRecoveryError::VtDisallocateBusy,
        };
        Ok(())
    }
    pub(super) fn pending_recovery(
        &mut self,
        lifecycle_id: &str,
        phase: &'static str,
        reason: WorkerExitClassification,
    ) -> Result<RecoverySeatReceipt, SessionError> {
        if !matches!(&self.phase, AdmissionPhase::PendingLifecycle { lifecycle_id: current, .. } if current == lifecycle_id)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.phase = AdmissionPhase::Free;
        self.lifecycle = SeatLifecycle::Recovering {
            lifecycle_id: lifecycle_id.to_owned(),
            phase,
            reason,
        };
        Ok(RecoverySeatReceipt {
            seat: self.seat.clone(),
            lifecycle_id: lifecycle_id.to_owned(),
            generation: self.generation,
        })
    }

    pub(super) fn issue_admin_finalization_receipt(
        &self,
        removed: &RecordRemovedReceipt,
    ) -> Result<AdminFinalizationReceipt, SessionError> {
        if removed.seat() != self.seat
            || !matches!(&self.lifecycle, SeatLifecycle::Quarantined { lifecycle_id, .. } if lifecycle_id == removed.lifecycle_id())
            || self.generation == 0
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        let lifecycle_id = match &self.lifecycle {
            SeatLifecycle::Quarantined { lifecycle_id, .. } => lifecycle_id.clone(),
            _ => return Err(SessionError::SessionSeatUnavailable),
        };
        Ok(AdminFinalizationReceipt {
            seat: removed.seat().to_owned(),
            lifecycle_id,
            seat_generation: self.generation,
            recovery_record_id: removed.record_id().to_owned(),
            finalization_sequence: removed.sequence(),
        })
    }

    pub(super) fn release_after_admin_finalization(
        &mut self,
        receipt: AdminFinalizationReceipt,
    ) -> Result<(), SessionError> {
        if receipt.seat != self.seat
            || receipt.seat_generation != self.generation
            || receipt.recovery_record_id.is_empty()
            || receipt.finalization_sequence == 0
            || !matches!(&self.lifecycle, SeatLifecycle::Quarantined { lifecycle_id, .. } if lifecycle_id == &receipt.lifecycle_id)
        {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.lifecycle = SeatLifecycle::Free;
        Ok(())
    }

    pub(in crate::launcher) fn cancel(
        &mut self,
        lease: AdmissionRollbackLease,
    ) -> Result<(), SessionError> {
        let matches = match &lease {
            AdmissionRollbackLease::Reserved(value) => self.matches_reserved(value),
            AdmissionRollbackLease::Pending(value) => self.matches_pending(value),
        };
        if !matches {
            return Err(SessionError::SessionSeatUnavailable);
        }
        self.phase = AdmissionPhase::Free;
        Ok(())
    }

    /// Consume a pre-commit lease after A4 cleanup has moved the runtime seat
    /// into recovery or quarantine.  This never publishes `Free` itself.
    fn matches_reserved(&self, lease: &AdmissionLease) -> bool {
        matches!(&self.phase, AdmissionPhase::Reserved { attempt_id, lifecycle_id, generation }
            if lease.seat == self.seat && lease.attempt_id == *attempt_id && lease.lifecycle_id == *lifecycle_id
                && lease.generation == *generation && lease.generation == self.generation)
    }

    pub(super) fn matches_pending(&self, lease: &PendingLifecycleLease) -> bool {
        matches!(&self.phase, AdmissionPhase::PendingLifecycle { attempt_id, lifecycle_id, generation }
            if lease.seat == self.seat && lease.attempt_id == *attempt_id && lease.lifecycle_id == *lifecycle_id
                && lease.generation == *generation && lease.generation == self.generation)
    }
}

impl AdmissionLease {
    pub(in crate::launcher) fn lifecycle_id(&self) -> &str {
        &self.lifecycle_id
    }

    pub(in crate::launcher) fn seat(&self) -> &str {
        &self.seat
    }

    pub(in crate::launcher) fn generation(&self) -> u64 {
        self.generation
    }

    pub(in crate::launcher) fn attempt_id(&self) -> u64 {
        self.attempt_id
    }
}

impl PendingLifecycleLease {
    pub(super) fn lifecycle_id(&self) -> &str {
        &self.lifecycle_id
    }
}

#[cfg(test)]
mod admin_receipt_tests {
    use super::*;

    fn quarantined() -> SeatAdmissionController {
        SeatAdmissionController::new(
            "seat0",
            SeatLifecycle::Quarantined {
                lifecycle_id: "recovery-lifecycle".into(),
                stage: EmergencyRecoveryStage::RecoveryRecordValidation,
                reason: SupervisorRecoveryError::BoundaryIdentityChanged,
            },
        )
    }

    fn receipt(lifecycle: &str, generation: u64, record: &str) -> AdminFinalizationReceipt {
        AdminFinalizationReceipt {
            seat: "seat0".into(),
            lifecycle_id: lifecycle.into(),
            seat_generation: generation,
            recovery_record_id: record.into(),
            finalization_sequence: 3,
        }
    }

    #[test]
    fn admin_release_requires_finalization_receipt() {
        let mut controller = quarantined();
        assert!(!controller.is_free());
        assert!(controller
            .release_after_admin_finalization(receipt("recovery-lifecycle", 1, "record"))
            .is_ok());
        assert!(controller.is_free());
    }

    #[test]
    fn foreign_admin_receipt_cannot_release_seat() {
        let mut controller = quarantined();
        assert!(controller
            .release_after_admin_finalization(receipt("foreign", 1, "record"))
            .is_err());
        assert!(!controller.is_free());
    }

    #[test]
    fn stale_admin_receipt_cannot_release_new_generation() {
        let mut controller = SeatAdmissionController::new("seat0", SeatLifecycle::Free);
        let lease = controller
            .reserve(
                "new".into(),
                RecoveryAdmissionState::Clear,
                PreviousVtIdentity { number: 1 },
            )
            .unwrap();
        let _ = controller.cancel(AdmissionRollbackLease::Reserved(lease));
        let _ = controller
            .reserve(
                "newer".into(),
                RecoveryAdmissionState::Clear,
                PreviousVtIdentity { number: 1 },
            )
            .unwrap();
        assert!(controller
            .release_after_admin_finalization(receipt("recovery-lifecycle", 1, "record"))
            .is_err());
    }

    #[test]
    fn admin_receipt_is_single_use() {
        let mut controller = quarantined();
        let first = receipt("recovery-lifecycle", 1, "record");
        assert!(controller.release_after_admin_finalization(first).is_ok());
        assert!(controller
            .release_after_admin_finalization(receipt("recovery-lifecycle", 1, "record"))
            .is_err());
    }

    #[test]
    fn lifecycle_string_cannot_release_admin_state() {
        let mut controller = quarantined();
        assert!(controller
            .release_after_admin_finalization(receipt("recovery-lifecycle", 1, "record"))
            .is_ok());
    }
}
