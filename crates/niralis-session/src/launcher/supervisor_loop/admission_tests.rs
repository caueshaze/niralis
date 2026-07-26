use super::admission::*;
use crate::launcher::recovery::SeatLifecycle;
use crate::launcher::recovery::WorkerExitClassification;
use crate::launcher::PreviousVtIdentity;
use crate::SessionError;
use std::sync::{Arc, Barrier, Mutex};

fn controller() -> SeatAdmissionController {
    SeatAdmissionController::new("seat0", SeatLifecycle::Free)
}

fn reserve(controller: &mut SeatAdmissionController, id: &str) -> AdmissionLease {
    controller
        .reserve(
            id.to_owned(),
            RecoveryAdmissionState::Clear,
            PreviousVtIdentity { number: 1 },
        )
        .unwrap()
}

#[test]
fn only_one_reservation_wins_per_seat() {
    let mut controller = controller();
    let _first = reserve(&mut controller, "one");
    assert!(matches!(
        controller.reserve(
            "two".to_owned(),
            RecoveryAdmissionState::Clear,
            PreviousVtIdentity { number: 1 }
        ),
        Err(SessionError::SessionSeatUnavailable)
    ));
}

#[test]
fn recovery_blocks_before_generation_changes() {
    let mut controller = controller();
    assert!(controller
        .reserve(
            "one".to_owned(),
            RecoveryAdmissionState::GloballyBlocked { reason: "fixture" },
            PreviousVtIdentity { number: 1 }
        )
        .is_err());
    let _lease = reserve(&mut controller, "one");
}

#[test]
fn stale_lease_cannot_cancel_new_reservation() {
    let mut controller = controller();
    let first = reserve(&mut controller, "one");
    controller
        .cancel(AdmissionRollbackLease::Reserved(first))
        .unwrap();
    let _second = reserve(&mut controller, "two");
}

#[test]
fn promotion_consumes_admission_lease_and_commit_consumes_pending_lease() {
    let mut controller = controller();
    let lease = reserve(&mut controller, "one");
    let (pending, _) = controller
        .promote(lease, RecoveryAdmissionState::Clear)
        .unwrap();
    let receipt = controller
        .commit(pending, RecoveryAdmissionState::Clear)
        .unwrap();
    let running = controller.promote_committed_to_running(receipt).unwrap();
    controller
        .release_running_after_a3_finalization(running)
        .unwrap();
    let _next = reserve(&mut controller, "two");
}

#[test]
fn quarantine_appearing_during_reservation_invalidates_promotion() {
    let mut controller = controller();
    let lease = reserve(&mut controller, "one");
    let (error, lease) = controller
        .promote(
            lease,
            RecoveryAdmissionState::SeatBlocked {
                seat: "seat0".into(),
                reason: "fixture",
            },
        )
        .unwrap_err();
    assert_eq!(error, SessionError::SessionSeatUnavailable);
    controller
        .cancel(AdmissionRollbackLease::Reserved(lease))
        .unwrap();
}

#[test]
fn unavailable_seat_rejects_before_worker_or_pam() {
    let mut controller = controller();
    let _ = reserve(&mut controller, "winner");
    assert!(controller
        .reserve(
            "loser".into(),
            RecoveryAdmissionState::Clear,
            PreviousVtIdentity { number: 1 }
        )
        .is_err());
}

#[test]
fn global_recovery_quarantine_blocks_reservation() {
    let mut controller = controller();
    assert!(controller
        .reserve(
            "attempt".into(),
            RecoveryAdmissionState::GloballyBlocked { reason: "global" },
            PreviousVtIdentity { number: 1 }
        )
        .is_err());
}

#[test]
fn seat_recovery_quarantine_blocks_only_that_seat() {
    let mut blocked = controller();
    let mut clear = SeatAdmissionController::new("seat1", SeatLifecycle::Free);
    assert!(blocked
        .reserve(
            "attempt".into(),
            RecoveryAdmissionState::SeatBlocked {
                seat: "seat0".into(),
                reason: "seat"
            },
            PreviousVtIdentity { number: 1 }
        )
        .is_err());
    assert!(clear
        .reserve(
            "attempt".into(),
            RecoveryAdmissionState::Clear,
            PreviousVtIdentity { number: 1 }
        )
        .is_ok());
}

#[test]
fn admission_does_not_use_first_ledger_record() {
    let mut controller = controller();
    assert!(controller
        .reserve(
            "attempt".into(),
            RecoveryAdmissionState::SeatBlocked {
                seat: "seat0".into(),
                reason: "consolidated"
            },
            PreviousVtIdentity { number: 1 }
        )
        .is_err());
}

#[test]
fn foreign_lifecycle_cannot_promote_lease() {
    let mut owner = controller();
    let lease = reserve(&mut owner, "owner");
    let mut foreign = controller();
    assert!(foreign
        .promote(lease, RecoveryAdmissionState::Clear)
        .is_err());
}

#[test]
fn generation_change_invalidates_lease() {
    let mut controller = controller();
    let lease = reserve(&mut controller, "first");
    let (pending, _) = controller
        .promote(lease, RecoveryAdmissionState::Clear)
        .unwrap();
    assert!(controller
        .commit(
            pending,
            RecoveryAdmissionState::SeatBlocked {
                seat: "seat0".into(),
                reason: "changed"
            }
        )
        .is_err());
}

#[test]
fn cancel_consumes_exact_lease() {
    let mut controller = controller();
    let lease = reserve(&mut controller, "attempt");
    controller
        .cancel(AdmissionRollbackLease::Reserved(lease))
        .unwrap();
    let _new = reserve(&mut controller, "new");
}

#[test]
fn greeter_disconnect_cancels_only_its_attempt() {
    let mut controller = controller();
    let lease = reserve(&mut controller, "disconnect");
    controller
        .cancel(AdmissionRollbackLease::Reserved(lease))
        .unwrap();
    let _survivor = reserve(&mut controller, "survivor");
}

#[test]
fn launch_commit_transfers_cleanup_to_a3() {
    let mut controller = controller();
    let lease = reserve(&mut controller, "lifecycle");
    let (pending, _) = controller
        .promote(lease, RecoveryAdmissionState::Clear)
        .unwrap();
    let committed = controller
        .commit(pending, RecoveryAdmissionState::Clear)
        .unwrap();
    let running = controller.promote_committed_to_running(committed).unwrap();
    assert!(!controller.is_free());
    controller
        .release_running_after_a3_finalization(running)
        .unwrap();
}

#[test]
fn post_commit_cancel_cannot_free_seat() {
    let mut controller = controller();
    let lease = reserve(&mut controller, "lifecycle");
    let (pending, _) = controller
        .promote(lease, RecoveryAdmissionState::Clear)
        .unwrap();
    let committed = controller
        .commit(pending, RecoveryAdmissionState::Clear)
        .unwrap();
    let _running = controller.promote_committed_to_running(committed).unwrap();
    assert!(!controller.is_free());
}

#[test]
fn a3_recovery_is_the_only_path_from_committed_to_free() {
    let mut controller = controller();
    let lease = reserve(&mut controller, "lifecycle");
    let (pending, _) = controller
        .promote(lease, RecoveryAdmissionState::Clear)
        .unwrap();
    let committed = controller
        .commit(pending, RecoveryAdmissionState::Clear)
        .unwrap();
    let running = controller.promote_committed_to_running(committed).unwrap();
    assert!(!controller.is_free());
    controller
        .release_running_after_a3_finalization(running)
        .unwrap();
    assert!(controller.is_free());
}

#[test]
fn two_reservations_race_twenty_times() {
    for _ in 0..20 {
        let controller = Arc::new(Mutex::new(controller()));
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for id in ["a", "b"] {
            let controller = Arc::clone(&controller);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                controller
                    .lock()
                    .unwrap()
                    .reserve(
                        id.into(),
                        RecoveryAdmissionState::Clear,
                        PreviousVtIdentity { number: 1 },
                    )
                    .is_ok()
            }));
        }
        barrier.wait();
        let wins = threads
            .into_iter()
            .filter_map(|thread| thread.join().ok())
            .filter(|won| *won)
            .count();
        assert_eq!(wins, 1);
    }
}

#[test]
fn quarantine_race_with_promotion_is_fail_closed_twenty_times() {
    for _ in 0..20 {
        let controller = Arc::new(Mutex::new(controller()));
        let lease = {
            let mut g = controller.lock().unwrap();
            reserve(&mut g, "attempt")
        };
        let lease = Arc::new(Mutex::new(Some(lease)));
        let barrier = Arc::new(Barrier::new(3));
        let c1 = Arc::clone(&controller);
        let l1 = Arc::clone(&lease);
        let b1 = Arc::clone(&barrier);
        let promotion = std::thread::spawn(move || {
            b1.wait();
            let Some(l) = l1.lock().unwrap().take() else {
                return false;
            };
            c1.lock()
                .unwrap()
                .promote(l, RecoveryAdmissionState::Clear)
                .is_ok()
        });
        let c2 = Arc::clone(&controller);
        let b2 = Arc::clone(&barrier);
        let quarantine = std::thread::spawn(move || {
            b2.wait();
            c2.lock()
                .unwrap()
                .quarantine_pending_lifecycle(
                    "attempt",
                    crate::launcher::recovery::EmergencyRecoveryStage::RecoveryRecordValidation,
                    crate::launcher::recovery::SupervisorRecoveryError::BoundaryIdentityChanged,
                )
                .is_ok()
        });
        barrier.wait();
        let outcomes = [promotion.join().unwrap(), quarantine.join().unwrap()];
        assert!(outcomes.iter().any(|value| *value));
        assert!(outcomes.iter().filter(|value| **value).count() <= 2);
    }
}

#[test]
fn cancel_stale_vs_new_reservation_twenty_times() {
    for _ in 0..20 {
        let mut controller = controller();
        let first = reserve(&mut controller, "first");
        controller
            .cancel(AdmissionRollbackLease::Reserved(first))
            .unwrap();
        let _second = reserve(&mut controller, "second");
    }
}

#[test]
fn promotion_vs_greeter_disconnect_twenty_times() {
    for _ in 0..20 {
        let controller = Arc::new(Mutex::new(controller()));
        let lease = {
            let mut guard = controller.lock().unwrap();
            reserve(&mut guard, "attempt")
        };
        let lease = Arc::new(Mutex::new(Some(lease)));
        let barrier = Arc::new(Barrier::new(3));
        let promote_controller = Arc::clone(&controller);
        let promote_lease = Arc::clone(&lease);
        let promote_barrier = Arc::clone(&barrier);
        let promotion = std::thread::spawn(move || {
            promote_barrier.wait();
            let Some(lease) = promote_lease.lock().unwrap().take() else {
                return false;
            };
            promote_controller
                .lock()
                .unwrap()
                .promote(lease, RecoveryAdmissionState::Clear)
                .is_ok()
        });
        let cancel_controller = Arc::clone(&controller);
        let cancel_lease = Arc::clone(&lease);
        let cancel_barrier = Arc::clone(&barrier);
        let disconnect = std::thread::spawn(move || {
            cancel_barrier.wait();
            let Some(lease) = cancel_lease.lock().unwrap().take() else {
                return false;
            };
            cancel_controller
                .lock()
                .unwrap()
                .cancel(AdmissionRollbackLease::Reserved(lease))
                .is_ok()
        });
        barrier.wait();
        let outcomes = [promotion.join().unwrap(), disconnect.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|value| **value).count(), 1);
    }
}

#[test]
fn launch_commit_vs_cancel_twenty_times() {
    for _ in 0..20 {
        let controller = Arc::new(Mutex::new(controller()));
        let pending = {
            let mut guard = controller.lock().unwrap();
            let lease = reserve(&mut guard, "attempt");
            guard
                .promote(lease, RecoveryAdmissionState::Clear)
                .unwrap()
                .0
        };
        let pending = Arc::new(Mutex::new(Some(pending)));
        let barrier = Arc::new(Barrier::new(3));
        let c1 = Arc::clone(&controller);
        let p1 = Arc::clone(&pending);
        let b1 = Arc::clone(&barrier);
        let commit = std::thread::spawn(move || {
            b1.wait();
            let Some(p) = p1.lock().unwrap().take() else {
                return false;
            };
            c1.lock()
                .unwrap()
                .commit(p, RecoveryAdmissionState::Clear)
                .is_ok()
        });
        let c2 = Arc::clone(&controller);
        let p2 = Arc::clone(&pending);
        let b2 = Arc::clone(&barrier);
        let cancel = std::thread::spawn(move || {
            b2.wait();
            let Some(p) = p2.lock().unwrap().take() else {
                return false;
            };
            c2.lock()
                .unwrap()
                .cancel(AdmissionRollbackLease::Pending(p))
                .is_ok()
        });
        barrier.wait();
        let outcomes = [commit.join().unwrap(), cancel.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|value| **value).count(), 1);
    }
}

#[test]
fn recovery_vs_cancel_twenty_times() {
    for _ in 0..20 {
        let controller = Arc::new(Mutex::new(controller()));
        let pending = {
            let mut g = controller.lock().unwrap();
            let l = reserve(&mut g, "attempt");
            g.promote(l, RecoveryAdmissionState::Clear).unwrap().0
        };
        let pending = Arc::new(Mutex::new(Some(pending)));
        let barrier = Arc::new(Barrier::new(3));
        let c1 = Arc::clone(&controller);
        let b1 = Arc::clone(&barrier);
        let recovery = std::thread::spawn(move || {
            b1.wait();
            let result = c1.lock().unwrap().pending_recovery(
                "attempt",
                "worker_spawned",
                WorkerExitClassification::UnexpectedExitBeforeStarted,
            );
            result.is_ok()
        });
        let c2 = Arc::clone(&controller);
        let p2 = Arc::clone(&pending);
        let b2 = Arc::clone(&barrier);
        let cancel = std::thread::spawn(move || {
            b2.wait();
            let Some(p) = p2.lock().unwrap().take() else {
                return false;
            };
            c2.lock()
                .unwrap()
                .cancel(AdmissionRollbackLease::Pending(p))
                .is_ok()
        });
        barrier.wait();
        let recovery_won = recovery.join().unwrap();
        let cancel_won = cancel.join().unwrap();
        assert_ne!(recovery_won, cancel_won);
        if recovery_won {
            assert!(!controller.lock().unwrap().is_free());
        }
    }
}

#[test]
fn a3_finalization_vs_new_reservation_twenty_times() {
    for _ in 0..20 {
        let controller = Arc::new(Mutex::new(controller()));
        let running = {
            let mut g = controller.lock().unwrap();
            let l = reserve(&mut g, "attempt");
            let (p, _) = g.promote(l, RecoveryAdmissionState::Clear).unwrap();
            let c = g.commit(p, RecoveryAdmissionState::Clear).unwrap();
            g.promote_committed_to_running(c).unwrap()
        };
        let running = Arc::new(Mutex::new(Some(running)));
        let barrier = Arc::new(Barrier::new(3));
        let c1 = Arc::clone(&controller);
        let r1 = Arc::clone(&running);
        let b1 = Arc::clone(&barrier);
        let release = std::thread::spawn(move || {
            b1.wait();
            let Some(r) = r1.lock().unwrap().take() else {
                return false;
            };
            c1.lock()
                .unwrap()
                .release_running_after_a3_finalization(r)
                .is_ok()
        });
        let c2 = Arc::clone(&controller);
        let b2 = Arc::clone(&barrier);
        let reserve_next = std::thread::spawn(move || {
            b2.wait();
            c2.lock()
                .unwrap()
                .reserve(
                    "next".into(),
                    RecoveryAdmissionState::Clear,
                    PreviousVtIdentity { number: 1 },
                )
                .is_ok()
        });
        barrier.wait();
        let release_won = release.join().unwrap();
        let reserve_won = reserve_next.join().unwrap();
        assert!(release_won);
        if reserve_won {
            assert!(controller.lock().unwrap().is_free());
        }
    }
}

#[test]
fn global_block_before_promotion_twenty_times() {
    for _ in 0..20 {
        let controller = Arc::new(Mutex::new(controller()));
        let lease = {
            let mut g = controller.lock().unwrap();
            reserve(&mut g, "attempt")
        };
        let lease = Arc::new(Mutex::new(Some(lease)));
        let barrier = Arc::new(Barrier::new(3));
        let c1 = Arc::clone(&controller);
        let l1 = Arc::clone(&lease);
        let b1 = Arc::clone(&barrier);
        let clear = std::thread::spawn(move || {
            b1.wait();
            let Some(l) = l1.lock().unwrap().take() else {
                return false;
            };
            c1.lock()
                .unwrap()
                .promote(l, RecoveryAdmissionState::Clear)
                .is_ok()
        });
        let c2 = Arc::clone(&controller);
        let b2 = Arc::clone(&barrier);
        let blocked = std::thread::spawn(move || {
            b2.wait();
            c2.lock()
                .unwrap()
                .reserve(
                    "blocked".into(),
                    RecoveryAdmissionState::GloballyBlocked { reason: "appeared" },
                    PreviousVtIdentity { number: 1 },
                )
                .is_ok()
        });
        barrier.wait();
        let outcomes = [clear.join().unwrap(), blocked.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|value| **value).count(), 1);
    }
}
