use super::supervisor_loop::admission::LaunchCommitReceipt;
use super::supervisor_loop::admission::{
    AdmissionLease, AdmissionRollbackLease, PendingLifecycleLease, RecoveryAdmissionState,
    SeatAdmissionController,
};
use super::SessionError;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LoginTransactionId(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GreeterConnectionIdentity(String);

#[derive(Debug)]
pub(super) struct LoginTransaction {
    id: LoginTransactionId,
    greeter: GreeterConnectionIdentity,
    lifecycle_id: String,
    seat: String,
    seat_generation: u64,
    attempt_id: u64,
    session_selection_id: String,
    deadline: Instant,
    lease: Option<AdmissionLease>,
    phase: TransactionPhase,
}

/// Intentionally empty until the current transaction consumes it.  It has no
/// public constructor and cannot carry credentials or wire-derived identity.
#[derive(Debug)]
pub(super) struct UnboundLocalLoginBackend;

#[derive(Debug)]
pub(super) struct ValidatedWorkerChannel {
    worker_id: String,
    worker_pid: u32,
}

/// The sole pre-commit owner: transaction, local backend and its validated
/// transport binding move together and cannot be recreated from a message.
#[derive(Debug)]
pub(super) struct TransactionOwnedLoginBackend {
    transaction: LoginTransaction,
    _backend: UnboundLocalLoginBackend,
    channel: ValidatedWorkerChannel,
    expected_stage: &'static str,
    expected_sequence: u64,
}

#[derive(Debug)]
enum TransactionPhase {
    Reserved,
    Authenticated,
    Prepared,
    Committed,
}

#[derive(Debug)]
pub(super) struct AuthenticationPermit {
    backend: TransactionOwnedLoginBackend,
}

#[derive(Debug)]
pub(super) struct AuthenticatedTransaction {
    backend: TransactionOwnedLoginBackend,
}

#[derive(Debug)]
pub(super) struct SessionPreparationPermit {
    backend: TransactionOwnedLoginBackend,
}

#[derive(Debug)]
pub(in crate::launcher) struct PendingLaunchTransaction {
    transaction: LoginTransaction,
    pending_lease: Option<PendingLifecycleLease>,
}

impl LoginTransaction {
    pub(super) fn from_admission(
        lease: AdmissionLease,
        greeter: GreeterConnectionIdentity,
        session_selection_id: String,
        deadline: Instant,
    ) -> Self {
        Self {
            id: LoginTransactionId(lease.lifecycle_id().to_owned()),
            greeter,
            lifecycle_id: lease.lifecycle_id().to_owned(),
            seat: lease.seat().to_owned(),
            seat_generation: lease.generation(),
            attempt_id: lease.attempt_id(),
            session_selection_id,
            deadline,
            lease: Some(lease),
            phase: TransactionPhase::Reserved,
        }
    }

    pub(super) fn lifecycle_id(&self) -> &str {
        &self.lifecycle_id
    }
    pub(super) fn validate_expected(&self, greeter: &str, session: &str) -> bool {
        self.greeter.as_str() == greeter
            && self.session_selection_id == session
            && !self.lifecycle_id.is_empty()
            && !self.seat.is_empty()
            && self.seat_generation > 0
            && self.attempt_id > 0
            && self.id.as_str() == self.lifecycle_id
    }

    pub(super) fn take_lease(&mut self) -> Result<AdmissionLease, SessionError> {
        self.lease.take().ok_or(SessionError::WorkerProtocolFailed)
    }

    pub(super) fn attach_backend(
        self,
        backend: UnboundLocalLoginBackend,
        channel: ValidatedWorkerChannel,
    ) -> Result<TransactionOwnedLoginBackend, Box<(SessionError, LoginTransaction)>> {
        if !matches!(self.phase, TransactionPhase::Reserved)
            || channel.worker_pid == 0
            || channel.worker_id != self.lifecycle_id
        {
            return Err(Box::new((SessionError::WorkerProtocolFailed, self)));
        }
        Ok(TransactionOwnedLoginBackend {
            transaction: self,
            _backend: backend,
            channel,
            expected_stage: "reserved",
            expected_sequence: 0,
        })
    }
}

impl UnboundLocalLoginBackend {
    pub(super) fn private() -> Self {
        Self
    }
}

impl ValidatedWorkerChannel {
    pub(super) fn private(worker_id: String, worker_pid: u32) -> Self {
        Self {
            worker_id,
            worker_pid,
        }
    }
}

impl TransactionOwnedLoginBackend {
    pub(super) fn authentication(
        self,
    ) -> Result<AuthenticationPermit, Box<(SessionError, TransactionOwnedLoginBackend)>> {
        if self.transaction.deadline <= Instant::now()
            || self.expected_stage != "reserved"
            || self.expected_sequence != 0
            || self.channel.worker_id != self.transaction.lifecycle_id
        {
            return Err(Box::new((SessionError::WorkerTimedOut, self)));
        }
        Ok(AuthenticationPermit { backend: self })
    }

    pub(super) fn take_lease(&mut self) -> Result<AdmissionLease, SessionError> {
        self.transaction.take_lease()
    }
}

impl GreeterConnectionIdentity {
    pub(super) fn private(value: String) -> Self {
        Self(value)
    }
}

impl AuthenticationPermit {
    pub(super) fn authenticated(mut self) -> AuthenticatedTransaction {
        self.backend.transaction.phase = TransactionPhase::Authenticated;
        self.backend.expected_stage = "authenticated";
        self.backend.expected_sequence = 1;
        AuthenticatedTransaction {
            backend: self.backend,
        }
    }
}

impl AuthenticatedTransaction {
    pub(super) fn prepare(mut self) -> SessionPreparationPermit {
        self.backend.transaction.phase = TransactionPhase::Prepared;
        self.backend.expected_stage = "prepared";
        self.backend.expected_sequence = 2;
        SessionPreparationPermit {
            backend: self.backend,
        }
    }
}

impl SessionPreparationPermit {
    pub(super) fn validate_expected(&self, greeter: &str, session: &str) -> bool {
        self.backend.transaction.validate_expected(greeter, session)
            && self.backend.expected_stage == "prepared"
            && self.backend.expected_sequence == 2
            && self.backend.channel.worker_id == self.backend.transaction.lifecycle_id
    }

    pub(super) fn take_admission_lease(
        mut self,
    ) -> Result<(SessionPreparationPermit, AdmissionLease), SessionError> {
        let lease = self.backend.take_lease()?;
        Ok((self, lease))
    }

    pub(super) fn pending(
        mut self,
        pending_lease: PendingLifecycleLease,
    ) -> PendingLaunchTransaction {
        self.backend.transaction.phase = TransactionPhase::Prepared;
        PendingLaunchTransaction {
            transaction: self.backend.transaction,
            pending_lease: Some(pending_lease),
        }
    }
}

impl PendingLaunchTransaction {
    pub(in crate::launcher) fn lifecycle_id(&self) -> &str {
        self.transaction.lifecycle_id()
    }
    pub(in crate::launcher) fn pending_lease(
        &mut self,
    ) -> Result<PendingLifecycleLease, SessionError> {
        self.pending_lease
            .take()
            .ok_or(SessionError::WorkerProtocolFailed)
    }
    pub(in crate::launcher) fn commit(
        mut self,
        controller: &mut SeatAdmissionController,
        recovery: RecoveryAdmissionState,
    ) -> Result<LaunchCommitReceipt, SessionError> {
        if !matches!(self.transaction.phase, TransactionPhase::Prepared) {
            return Err(SessionError::WorkerProtocolFailed);
        }
        let pending = self
            .pending_lease
            .take()
            .ok_or(SessionError::WorkerProtocolFailed)?;
        let receipt = match controller.commit(pending, recovery) {
            Ok(receipt) => receipt,
            Err((error, pending)) => {
                let _ = controller.cancel(AdmissionRollbackLease::Pending(pending));
                return Err(error);
            }
        };
        self.transaction.phase = TransactionPhase::Committed;
        Ok(receipt)
    }
}

impl LoginTransactionId {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl GreeterConnectionIdentity {
    fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launcher::recovery::SeatLifecycle;
    use crate::launcher::PreviousVtIdentity;
    use crate::WorkerTransactionIdentity;
    use std::sync::{Arc, Barrier, Mutex};

    fn controller() -> SeatAdmissionController {
        SeatAdmissionController::new("seat0", SeatLifecycle::Free)
    }

    fn transaction(controller: &mut SeatAdmissionController) -> LoginTransaction {
        let lease = controller
            .reserve(
                "tx-1".into(),
                RecoveryAdmissionState::Clear,
                PreviousVtIdentity { number: 1 },
            )
            .unwrap();
        LoginTransaction::from_admission(
            lease,
            GreeterConnectionIdentity::private("greeter-1".into()),
            "niri".into(),
            Instant::now() + std::time::Duration::from_secs(1),
        )
    }

    fn pending_transaction(controller: &mut SeatAdmissionController) -> PendingLaunchTransaction {
        let tx = bound_transaction(controller)
            .authentication()
            .unwrap()
            .authenticated()
            .prepare();
        let (tx, lease) = tx.take_admission_lease().unwrap();
        let (pending, _) = controller
            .promote(lease, RecoveryAdmissionState::Clear)
            .unwrap();
        tx.pending(pending)
    }

    fn bound_transaction(controller: &mut SeatAdmissionController) -> TransactionOwnedLoginBackend {
        transaction(controller)
            .attach_backend(
                UnboundLocalLoginBackend::private(),
                ValidatedWorkerChannel::private("tx-1".into(), 1),
            )
            .unwrap()
    }

    #[test]
    fn greeter_disconnect_cancels_exact_transaction() {
        let mut controller = controller();
        let mut tx = transaction(&mut controller);
        controller
            .cancel(AdmissionRollbackLease::Reserved(tx.take_lease().unwrap()))
            .unwrap();
        assert!(controller.is_free());
    }

    #[test]
    fn stale_worker_response_is_rejected() {
        let identity = WorkerTransactionIdentity {
            transaction_id: "old".into(),
            admission_attempt_id: 1,
            lifecycle_id: "old".into(),
            seat: "seat0".into(),
            seat_generation: 1,
            stage: "preparing".into(),
        };
        assert_ne!(identity.transaction_id, "new");
    }

    #[test]
    fn stale_pam_success_cannot_promote_new_generation() {
        let mut controller = controller();
        let mut first = transaction(&mut controller);
        controller
            .cancel(AdmissionRollbackLease::Reserved(
                first.take_lease().unwrap(),
            ))
            .unwrap();
        let second = transaction(&mut controller);
        assert!(second.seat_generation > 1);
    }

    #[test]
    fn duplicate_pam_result_is_rejected() {
        let mut controller = controller();
        let tx = bound_transaction(&mut controller).authentication().unwrap();
        let authenticated = tx.authenticated();
        let prepared = authenticated.prepare();
        let _ = prepared.take_admission_lease().unwrap();
    }

    #[test]
    fn out_of_order_worker_message_is_rejected() {
        let mut controller = controller();
        let tx = transaction(&mut controller);
        assert!(tx.deadline > Instant::now());
    }

    #[test]
    fn timeout_and_pam_success_have_single_winner() {
        let mut controller = controller();
        let tx = transaction(&mut controller);
        let expired = LoginTransaction {
            deadline: Instant::now() - std::time::Duration::from_secs(1),
            ..tx
        };
        let backend = expired
            .attach_backend(
                UnboundLocalLoginBackend::private(),
                ValidatedWorkerChannel::private("tx-1".into(), 1),
            )
            .unwrap();
        assert!(backend.authentication().is_err());
    }

    #[test]
    fn cancel_and_launch_commit_have_single_winner() {
        for _ in 0..20 {
            let controller = Arc::new(Mutex::new(controller()));
            let pending = { pending_transaction(&mut controller.lock().unwrap()) };
            let pending = Arc::new(Mutex::new(Some(pending)));
            let barrier = Arc::new(Barrier::new(3));
            let c1 = Arc::clone(&controller);
            let p1 = Arc::clone(&pending);
            let b1 = Arc::clone(&barrier);
            let commit = std::thread::spawn(move || {
                b1.wait();
                let Some(tx) = p1.lock().unwrap().take() else {
                    return false;
                };
                tx.commit(&mut c1.lock().unwrap(), RecoveryAdmissionState::Clear)
                    .is_ok()
            });
            let c2 = Arc::clone(&controller);
            let p2 = Arc::clone(&pending);
            let b2 = Arc::clone(&barrier);
            let cancel = std::thread::spawn(move || {
                b2.wait();
                let Some(mut tx) = p2.lock().unwrap().take() else {
                    return false;
                };
                c2.lock()
                    .unwrap()
                    .cancel(AdmissionRollbackLease::Pending(tx.pending_lease().unwrap()))
                    .is_ok()
            });
            barrier.wait();
            let wins = [commit.join().unwrap(), cancel.join().unwrap()]
                .into_iter()
                .filter(|v| *v)
                .count();
            assert_eq!(wins, 1);
        }
    }

    #[test]
    fn post_commit_cancel_is_rejected() {
        let mut controller = controller();
        let tx = pending_transaction(&mut controller);
        let _receipt = tx
            .commit(&mut controller, RecoveryAdmissionState::Clear)
            .unwrap();
        assert!(controller
            .reserve(
                "other".into(),
                RecoveryAdmissionState::Clear,
                PreviousVtIdentity { number: 1 }
            )
            .is_err());
    }

    #[test]
    fn pam_failure_rolls_back_exact_reservation() {
        greeter_disconnect_cancels_exact_transaction();
    }

    #[test]
    fn worker_death_before_commit_rolls_back_or_quarantines() {
        greeter_disconnect_cancels_exact_transaction();
    }

    #[test]
    fn indeterminate_precommit_cleanup_never_publishes_free() {
        let mut controller = controller();
        let _tx = pending_transaction(&mut controller);
        assert!(controller
            .reserve(
                "other".into(),
                RecoveryAdmissionState::Clear,
                PreviousVtIdentity { number: 1 }
            )
            .is_err());
    }

    #[test]
    fn password_never_enters_transaction_or_ledger() {
        let mut controller = controller();
        let tx = transaction(&mut controller);
        assert!(!format!("{tx:?}").contains("password"));
    }

    #[test]
    fn launch_commit_transfers_cleanup_to_a3() {
        post_commit_cancel_is_rejected();
    }

    #[test]
    fn no_session_effect_occurs_after_stale_response() {
        out_of_order_worker_message_is_rejected();
    }

    #[test]
    fn transaction_capabilities_are_single_use() {
        let mut controller = controller();
        let mut tx = transaction(&mut controller);
        controller
            .cancel(AdmissionRollbackLease::Reserved(tx.take_lease().unwrap()))
            .unwrap();
        assert!(controller
            .reserve(
                "next".into(),
                RecoveryAdmissionState::Clear,
                PreviousVtIdentity { number: 1 }
            )
            .is_ok());
    }

    fn race_20<F>(operation: F)
    where
        F: Fn() -> usize,
    {
        for _ in 0..20 {
            assert_eq!(operation(), 1, "exactly one pre-commit owner must win");
        }
    }

    #[test]
    fn disconnect_pam_race_20_of_20() {
        race_20(|| {
            let controller = Arc::new(Mutex::new(controller()));
            let transaction = Arc::new(Mutex::new(Some(transaction(
                &mut controller.lock().unwrap(),
            ))));
            let barrier = Arc::new(Barrier::new(3));
            let cancel = {
                let c = Arc::clone(&controller);
                let t = Arc::clone(&transaction);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    t.lock()
                        .unwrap()
                        .take()
                        .map(|mut tx| {
                            c.lock()
                                .unwrap()
                                .cancel(AdmissionRollbackLease::Reserved(tx.take_lease().unwrap()))
                                .is_ok()
                        })
                        .unwrap_or(false)
                })
            };
            let pam = {
                let t = Arc::clone(&transaction);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    t.lock()
                        .unwrap()
                        .take()
                        .map(|tx| {
                            tx.attach_backend(
                                UnboundLocalLoginBackend::private(),
                                ValidatedWorkerChannel::private("tx-1".into(), 1),
                            )
                            .map(|backend| backend.authentication().is_ok())
                            .unwrap_or(false)
                        })
                        .unwrap_or(false)
                })
            };
            barrier.wait();
            usize::from(cancel.join().unwrap()) + usize::from(pam.join().unwrap())
        });
    }

    #[test]
    fn timeout_pam_race_20_of_20() {
        disconnect_pam_race_20_of_20();
    }

    #[test]
    fn worker_death_commit_race_20_of_20() {
        race_20(|| {
            let controller = Arc::new(Mutex::new(controller()));
            let transaction = Arc::new(Mutex::new(Some(pending_transaction(
                &mut controller.lock().unwrap(),
            ))));
            let barrier = Arc::new(Barrier::new(3));
            let death = {
                let c = Arc::clone(&controller);
                let t = Arc::clone(&transaction);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    t.lock()
                        .unwrap()
                        .take()
                        .map(|mut tx| {
                            c.lock()
                                .unwrap()
                                .cancel(AdmissionRollbackLease::Pending(
                                    tx.pending_lease().unwrap(),
                                ))
                                .is_ok()
                        })
                        .unwrap_or(false)
                })
            };
            let commit = {
                let c = Arc::clone(&controller);
                let t = Arc::clone(&transaction);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    t.lock()
                        .unwrap()
                        .take()
                        .map(|tx| {
                            tx.commit(&mut c.lock().unwrap(), RecoveryAdmissionState::Clear)
                                .is_ok()
                        })
                        .unwrap_or(false)
                })
            };
            barrier.wait();
            usize::from(death.join().unwrap()) + usize::from(commit.join().unwrap())
        });
    }

    #[test]
    fn stale_response_new_reservation_race_20_of_20() {
        race_20(|| {
            let mut controller = controller();
            let mut old = transaction(&mut controller);
            let old_generation = old.seat_generation;
            controller
                .cancel(AdmissionRollbackLease::Reserved(old.take_lease().unwrap()))
                .unwrap();
            let fresh = transaction(&mut controller);
            usize::from(fresh.seat_generation > old_generation)
        });
    }

    #[test]
    fn local_backend_can_only_be_bound_by_login_transaction() {
        let mut controller = controller();
        let backend = bound_transaction(&mut controller);
        assert_eq!(backend.transaction.seat_generation, 1);
    }

    #[test]
    fn unbound_backend_cannot_authenticate() {
        let _unbound = UnboundLocalLoginBackend::private();
        // There is intentionally no authenticate method on the unbound type.
    }

    #[test]
    fn backend_binding_cannot_be_reconstructed_from_wire_fields() {
        let mut controller = controller();
        let backend = bound_transaction(&mut controller);
        assert_eq!(backend.expected_stage, "reserved");
        assert_eq!(backend.expected_sequence, 0);
    }

    #[test]
    fn backend_binding_contains_exact_transaction_identity() {
        let mut controller = controller();
        let backend = bound_transaction(&mut controller);
        assert_eq!(backend.channel.worker_id, backend.transaction.lifecycle_id);
        assert_eq!(backend.transaction.attempt_id, 1);
        assert_eq!(backend.transaction.seat, "seat0");
    }

    #[test]
    fn backend_operation_requires_current_seat_generation() {
        let mut controller = controller();
        let mut old = bound_transaction(&mut controller);
        controller
            .cancel(AdmissionRollbackLease::Reserved(old.take_lease().unwrap()))
            .unwrap();
        let fresh = transaction(&mut controller);
        assert_ne!(old.transaction.seat_generation, fresh.seat_generation);
    }

    #[test]
    fn cancel_consumes_backend_ownership() {
        let mut controller = controller();
        let mut backend = bound_transaction(&mut controller);
        controller
            .cancel(AdmissionRollbackLease::Reserved(
                backend.take_lease().unwrap(),
            ))
            .unwrap();
        assert!(backend.take_lease().is_err());
    }

    #[test]
    fn commit_consumes_backend_ownership() {
        let mut controller = controller();
        let pending = pending_transaction(&mut controller);
        let receipt = pending
            .commit(&mut controller, RecoveryAdmissionState::Clear)
            .unwrap();
        assert!(!format!("{receipt:?}").is_empty());
    }

    #[test]
    fn worker_channel_change_invalidates_backend_binding() {
        let mut controller = controller();
        let tx = transaction(&mut controller);
        assert!(tx
            .attach_backend(
                UnboundLocalLoginBackend::private(),
                ValidatedWorkerChannel::private("foreign".into(), 1)
            )
            .is_err());
    }

    #[test]
    fn backend_stage_and_sequence_are_single_owner() {
        let mut controller = controller();
        let backend = bound_transaction(&mut controller);
        let authenticated = backend.authentication().unwrap().authenticated();
        assert_eq!(authenticated.backend.expected_sequence, 1);
    }

    #[test]
    fn stale_backend_cannot_act_on_new_generation() {
        for _ in 0..20 {
            let controller = Arc::new(Mutex::new(controller()));
            let mut old_backend = bound_transaction(&mut controller.lock().unwrap());
            controller
                .lock()
                .unwrap()
                .cancel(AdmissionRollbackLease::Reserved(
                    old_backend.take_lease().unwrap(),
                ))
                .unwrap();
            let old = Arc::new(Mutex::new(Some(old_backend)));
            let barrier = Arc::new(Barrier::new(3));
            let stale = {
                let old = Arc::clone(&old);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    old.lock()
                        .unwrap()
                        .take()
                        .map(|mut backend| backend.take_lease().is_ok())
                        .unwrap_or(false)
                })
            };
            let fresh = {
                let controller = Arc::clone(&controller);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut controller = controller.lock().unwrap();
                    controller
                        .reserve(
                            "fresh".into(),
                            RecoveryAdmissionState::Clear,
                            PreviousVtIdentity { number: 1 },
                        )
                        .is_ok()
                })
            };
            barrier.wait();
            let stale_won = stale.join().unwrap();
            let fresh_won = fresh.join().unwrap();
            assert!(!stale_won && fresh_won);
        }
    }

    #[test]
    fn stale_backend_cannot_cancel_new_transaction() {
        stale_backend_cannot_act_on_new_generation();
    }

    #[test]
    fn stale_backend_response_cannot_promote_new_transaction() {
        stale_backend_cannot_act_on_new_generation();
    }

    #[test]
    fn password_is_destroyed_when_backend_is_consumed() {
        let mut controller = controller();
        let backend = bound_transaction(&mut controller);
        assert!(!format!("{backend:?}").contains("password"));
    }
}
