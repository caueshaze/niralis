    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct TestObserver(OwnedFd);
    impl crate::payload_scope::PayloadBoundaryObserver for TestObserver {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
        fn consume_wakeup(&mut self) -> Result<(), crate::payload_scope::PayloadScopeError> {
            let mut value = 0_u64;
            let read =
                unsafe { libc::read(self.0.as_raw_fd(), (&mut value as *mut u64).cast(), 8) };
            (read == 8)
                .then_some(())
                .ok_or(crate::payload_scope::PayloadScopeError::ObserverFailed)
        }
    }

    struct TestScope {
        identity: niralis_session::PayloadScopeIdentity,
        event_fd: OwnedFd,
        requests: Arc<AtomicUsize>,
        fail: Option<crate::payload_scope::PayloadScopeError>,
    }
    impl TestScope {
        fn new(fail: Option<crate::payload_scope::PayloadScopeError>) -> Self {
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            Self {
                identity: niralis_session::PayloadScopeIdentity {
                    unit_name: "niralis-payload-00000000000000000000000000000000.scope".into(),
                    invocation_id: "00000000000000000000000000000000".into(),
                    expected_uid: 1000,
                    logind_session_id: niralis_session::LogindSessionId::new("1".into()).unwrap(),
                },
                event_fd: unsafe { OwnedFd::from_raw_fd(fd) },
                requests: Arc::new(AtomicUsize::new(0)),
                fail,
            }
        }
    }
    impl crate::payload_scope::AuthoritativePayloadScope for TestScope {
        fn identity(&self) -> &niralis_session::PayloadScopeIdentity {
            &self.identity
        }
        fn control_group(&self) -> &str {
            "/test"
        }
        fn cleanup(
            self: Box<Self>,
            _: std::time::Instant,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            Ok(())
        }
        fn create_boundary_observer(
            &self,
        ) -> Result<
            Box<dyn crate::payload_scope::PayloadBoundaryObserver>,
            crate::payload_scope::PayloadScopeError,
        > {
            let fd = unsafe { libc::fcntl(self.event_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                Err(crate::payload_scope::PayloadScopeError::ObserverFailed)
            } else {
                Ok(Box::new(TestObserver(unsafe { OwnedFd::from_raw_fd(fd) })))
            }
        }
        fn request_graceful_termination(
            &self,
        ) -> Result<(), crate::payload_scope::PayloadScopeError> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            self.fail.clone().map_or(Ok(()), Err)
        }
        fn prove_empty_boundary(
            &self,
            leader_exit: &LeaderExit,
        ) -> Result<BoundaryEmptyProof, crate::payload_scope::PayloadScopeError> {
            if let Some(error) = &self.fail {
                return Err(error.clone());
            }
            Ok(BoundaryEmptyProof::new(
                &self.identity,
                self.control_group(),
                leader_exit.clone(),
            ))
        }
    }
