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

