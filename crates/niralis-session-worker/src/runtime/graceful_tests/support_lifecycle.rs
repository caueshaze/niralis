    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
        Arc, Mutex,
    };

    static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct OrderedTransaction {
        events: Arc<Mutex<Vec<&'static str>>>,
        close_fails: bool,
    }
    impl niralis_auth::AuthenticatedTransaction for OrderedTransaction {
        fn user(&self) -> &niralis_auth::AuthenticatedUser {
            panic!("unused by finalizer")
        }
        fn open_session(
            &mut self,
            _: &niralis_auth::PamSessionMetadata,
        ) -> Result<(), niralis_auth::AuthSessionError> {
            panic!("unused by finalizer")
        }
        fn session_environment(
            &mut self,
        ) -> Result<niralis_auth::PamSessionEnvironment, niralis_auth::AuthSessionError> {
            panic!("unused by finalizer")
        }
        fn close_session(&mut self) -> Result<(), niralis_auth::AuthSessionError> {
            self.events.lock().unwrap().push("pam_close_started");
            if self.close_fails {
                Err(niralis_auth::AuthSessionError::CloseFailed)
            } else {
                self.events.lock().unwrap().push("pam_close_completed");
                Ok(())
            }
        }
    }
    impl Drop for OrderedTransaction {
        fn drop(&mut self) {
            self.events.lock().unwrap().push("pam_dropped");
        }
    }

    struct OrderedLease {
        events: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }
    impl crate::VirtualTerminalLease for OrderedLease {
        fn seat(&self) -> &niralis_auth::SeatId {
            panic!("unused by finalizer")
        }
        fn vtnr(&self) -> niralis_auth::VirtualTerminalId {
            niralis_auth::VirtualTerminalId::new(1).unwrap()
        }
        fn duplicate_terminal_fd(&self) -> Result<OwnedFd, crate::VirtualTerminalError> {
            panic!("unused by finalizer")
        }
        fn activate(&mut self, _: Duration) -> Result<(), crate::VirtualTerminalError> {
            panic!("unused by finalizer")
        }
        fn release(&mut self) -> Result<(), crate::VirtualTerminalError> {
            self.events.lock().unwrap().push("vt_released");
            if self.fail {
                Err(crate::VirtualTerminalError::CleanupFailed)
            } else {
                Ok(())
            }
        }
    }

    struct OrderedScope {
        identity: niralis_session::PayloadScopeIdentity,
        events: Arc<Mutex<Vec<&'static str>>>,
        unref_fails: bool,
    }
    impl crate::payload_scope::AuthoritativePayloadScope for OrderedScope {
        fn identity(&self) -> &niralis_session::PayloadScopeIdentity {
            &self.identity
        }
        fn control_group(&self) -> &str {
            "/test"
        }
        fn cleanup(
            self: Box<Self>,
            _: Instant,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            Ok(())
        }
        fn release_pin(&mut self) -> Result<(), crate::payload_scope::PayloadScopeError> {
            self.events.lock().unwrap().push("unit_unref_attempted");
            if self.unref_fails {
                Err(crate::payload_scope::PayloadScopeError::UnrefFailed)
            } else {
                Ok(())
            }
        }
    }

    struct EventObserver(OwnedFd);
    impl crate::payload_scope::PayloadBoundaryObserver for EventObserver {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
        fn poll_events(&self) -> libc::c_short {
            libc::POLLIN
        }
        fn consume_wakeup(&mut self) -> Result<(), crate::payload_scope::PayloadScopeError> {
            read_event(self.0.as_raw_fd())
                .then_some(())
                .ok_or(crate::payload_scope::PayloadScopeError::ObserverFailed)
        }
    }

    struct EventScope {
        identity: niralis_session::PayloadScopeIdentity,
        boundary_fd: OwnedFd,
        pid_fd: RawFd,
        cooperative: bool,
        terminal: AtomicBool,
        requests: AtomicUsize,
        unrefs: AtomicUsize,
        fail: Option<crate::payload_scope::PayloadScopeError>,
        observe_fail: Option<crate::payload_scope::PayloadScopeError>,
    }
