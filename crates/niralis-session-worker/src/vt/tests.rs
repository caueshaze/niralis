
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct FakeLease {
        seat: SeatId,
        vtnr: VirtualTerminalId,
        releases: Arc<AtomicUsize>,
        release_result: Result<(), VirtualTerminalError>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum VtOperation {
        Active,
        Activate(u32),
        CloseTerminal,
        Disallocate(u32),
    }

    struct FakeVtControl {
        active: VecDeque<Result<u32, libc::c_int>>,
        activate: Result<(), libc::c_int>,
        disallocate: Result<(), libc::c_int>,
        operations: Vec<VtOperation>,
    }

    impl FakeVtControl {
        fn with_active(active: impl IntoIterator<Item = u32>) -> Self {
            Self {
                active: active.into_iter().map(Ok).collect(),
                activate: Ok(()),
                disallocate: Ok(()),
                operations: Vec::new(),
            }
        }
    }

    impl VtControlOperations for FakeVtControl {
        fn active(&mut self) -> Result<u32, libc::c_int> {
            self.operations.push(VtOperation::Active);
            self.active.pop_front().expect("scripted active VT state")
        }

        fn activate(&mut self, number: u32) -> Result<(), libc::c_int> {
            self.operations.push(VtOperation::Activate(number));
            self.activate
        }

        fn disallocate(&mut self, number: u32) -> Result<(), libc::c_int> {
            self.operations.push(VtOperation::Disallocate(number));
            self.disallocate
        }
    }

    impl VtReleaseOperations for FakeVtControl {
        fn close_terminal(&mut self) {
            self.operations.push(VtOperation::CloseTerminal);
        }
    }

    impl VirtualTerminalLease for FakeLease {
        fn seat(&self) -> &SeatId {
            &self.seat
        }
        fn vtnr(&self) -> VirtualTerminalId {
            self.vtnr
        }
        fn duplicate_terminal_fd(&self) -> Result<OwnedFd, VirtualTerminalError> {
            Err(VirtualTerminalError::OperationFailed)
        }
        fn activate(&mut self, _wait: Duration) -> Result<(), VirtualTerminalError> {
            Ok(())
        }
        fn release(&mut self) -> Result<(), VirtualTerminalError> {
            self.releases.fetch_add(1, Ordering::SeqCst);
            self.release_result.clone()
        }
    }

    #[test]
    fn guard_release_is_idempotent_and_does_not_touch_real_vt() {
        let releases = Arc::new(AtomicUsize::new(0));
        let seat = SeatId::new("seat0".to_owned()).unwrap();
        let vtnr = VirtualTerminalId::new(2).unwrap();
        let mut guard = VirtualTerminalGuard::new(Box::new(FakeLease {
            seat,
            vtnr,
            releases: releases.clone(),
            release_result: Ok(()),
        }));
        guard.release().unwrap();
        guard.release().unwrap();
        assert_eq!(releases.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn guard_failed_release_is_not_retried_explicitly_or_from_drop() {
        let releases = Arc::new(AtomicUsize::new(0));
        let expected = VirtualTerminalError::CleanupOperationFailed {
            stage: "disallocate",
            errno: libc::EBUSY,
        };
        {
            let mut guard = VirtualTerminalGuard::new(Box::new(FakeLease {
                seat: SeatId::new("seat0".to_owned()).unwrap(),
                vtnr: VirtualTerminalId::new(2).unwrap(),
                releases: releases.clone(),
                release_result: Err(expected.clone()),
            }));
            assert_eq!(guard.release(), Err(expected.clone()));
            assert_eq!(guard.release(), Err(expected));
        }
        assert_eq!(releases.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn active_owned_vt_restores_previous_before_disallocate() {
        let mut control = FakeVtControl::with_active([2, 1]);
        release_allocated_terminal(&mut control, 2, 1, Duration::ZERO).unwrap();
        assert_eq!(
            control.operations,
            [
                VtOperation::Active,
                VtOperation::Activate(1),
                VtOperation::Active,
                VtOperation::CloseTerminal,
                VtOperation::Disallocate(2),
            ]
        );
    }

    #[test]
    fn already_inactive_owned_vt_does_not_override_current_terminal() {
        let mut control = FakeVtControl::with_active([3]);
        release_allocated_terminal(&mut control, 2, 1, Duration::ZERO).unwrap();
        assert_eq!(
            control.operations,
            [
                VtOperation::Active,
                VtOperation::CloseTerminal,
                VtOperation::Disallocate(2),
            ]
        );
    }

    #[test]
    fn previous_vt_restore_timeout_never_disallocates_active_vt() {
        let mut control = FakeVtControl::with_active([2, 2]);
        assert_eq!(
            release_allocated_terminal(&mut control, 2, 1, Duration::ZERO),
            Err(VirtualTerminalError::CleanupTimedOut)
        );
        assert_eq!(
            control.operations,
            [
                VtOperation::Active,
                VtOperation::Activate(1),
                VtOperation::Active,
            ]
        );
    }

    #[test]
    fn disallocate_failure_preserves_stage_and_errno() {
        let mut control = FakeVtControl::with_active([1]);
        control.disallocate = Err(libc::EBUSY);
        assert_eq!(
            release_allocated_terminal(&mut control, 2, 1, Duration::ZERO),
            Err(VirtualTerminalError::CleanupOperationFailed {
                stage: "disallocate",
                errno: libc::EBUSY,
            })
        );
        assert_eq!(
            control.operations,
            [
                VtOperation::Active,
                VtOperation::CloseTerminal,
                VtOperation::Disallocate(2),
            ]
        );
    }

    #[test]
    fn closing_owned_terminal_state_drops_the_worker_tty_descriptor() {
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let mut state = OwnedTerminalHandleState::Held(writer);

        state.close_terminal();

        assert!(matches!(state, OwnedTerminalHandleState::TerminalClosed));
        let mut byte = 0_u8;
        assert_eq!(
            unsafe {
                libc::read(
                    reader.as_raw_fd(),
                    std::ptr::from_mut(&mut byte).cast(),
                    1,
                )
            },
            0,
            "dropping the terminal handle must close the pipe's only writer"
        );
    }

    #[test]
    fn graphical_seat_query_distinguishes_not_graphical_from_query_failure() {
        let not_graphical = ensure_graphical_seat("seat0", |_| Ok(0)).unwrap_err();
        let query_failure = ensure_graphical_seat("seat0", |_| Ok(-libc::EACCES)).unwrap_err();

        assert_eq!(not_graphical, VirtualTerminalError::SeatNotGraphical);
        assert_eq!(
            query_failure,
            VirtualTerminalError::SeatQueryFailed(-libc::EACCES)
        );
    }

    #[test]
    fn graphical_seat_query_preserves_loader_and_symbol_failures() {
        let library_failure =
            ensure_graphical_seat("seat0", |_| Err(VirtualTerminalError::LibraryUnavailable))
                .unwrap_err();
        let symbol_failure =
            ensure_graphical_seat("seat0", |_| Err(VirtualTerminalError::SymbolUnavailable))
                .unwrap_err();

        assert_eq!(library_failure, VirtualTerminalError::LibraryUnavailable);
        assert_eq!(symbol_failure, VirtualTerminalError::SymbolUnavailable);
    }

    #[test]
    fn graphical_seat_query_rejects_nul_before_querying() {
        let error = ensure_graphical_seat("seat\0invalid", |_| {
            panic!("invalid seat names must not reach libsystemd")
        })
        .unwrap_err();

        assert_eq!(error, VirtualTerminalError::InvalidSeatName);
    }
}
