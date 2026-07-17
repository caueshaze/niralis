    #[test]
    fn descriptors_are_cloexec_nonblocking_and_timer_is_one_shot() {
        let timer = GraceTimerFd::new().unwrap();
        let fd_flags = unsafe { libc::fcntl(timer.as_raw_fd(), libc::F_GETFD) };
        let status_flags = unsafe { libc::fcntl(timer.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
        assert_ne!(status_flags & libc::O_NONBLOCK, 0);
        assert!(!timer.consume().unwrap());
        timer.arm_once(Duration::from_millis(1)).unwrap();
        let mut pollfd = libc::pollfd {
            fd: timer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 1000) }, 1);
        assert!(timer.consume().unwrap());
        assert!(!timer.consume().unwrap());
    }
    #[test]
    fn payload_restore_unblocks_managed_signals() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let signals = WorkerSignalFd::install().unwrap();
            assert!(signals.as_raw_fd() >= 0);
            restore_payload_signal_state().unwrap();
            let mut current = unsafe { std::mem::zeroed::<libc::sigset_t>() };
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current) };
            let clean = SIGNALS
                .iter()
                .all(|signal| unsafe { libc::sigismember(&current, *signal) } == 0);
            std::mem::forget(signals);
            unsafe { libc::_exit(if clean { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
    #[test]
    fn leader_exit_is_typed_without_text_parsing() {
        assert_eq!(
            LeaderExit::from_status(std::process::ExitStatus::from_raw(0)),
            LeaderExit::ExitedZero
        );
        assert_eq!(
            LeaderExit::from_status(std::process::ExitStatus::from_raw(42 << 8)),
            LeaderExit::ExitedNonZero(42)
        );
        assert_eq!(
            LeaderExit::from_status(std::process::ExitStatus::from_raw(libc::SIGSEGV)),
            LeaderExit::KilledBySignal(libc::SIGSEGV)
        );
    }

    #[test]
    fn coordinator_preserves_first_cause_and_requests_once() {
        let scope = TestScope::new(None);
        let requests = scope.requests.clone();
        let mut coordinator = GracefulTerminationCoordinator::new().unwrap();
        assert!(coordinator
            .begin(
                TerminationCause::InternalTerminateRequest,
                Duration::from_secs(1),
                &scope
            )
            .unwrap()
            .is_some());
        assert!(coordinator
            .begin(
                TerminationCause::WorkerSignal(WorkerTerminationSignal::Sighup),
                Duration::from_secs(2),
                &scope
            )
            .unwrap()
            .is_none());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        coordinator.record_leader_exit(LeaderExit::ExitedNonZero(42));
        coordinator.record_leader_exit(LeaderExit::ExitedZero);
        assert_eq!(
            coordinator.deadline_expired(),
            GracefulTerminationOutcome::DeadlineExpired {
                cause: TerminationCause::InternalTerminateRequest,
                leader_exit: Some(LeaderExit::ExitedNonZero(42))
            }
        );
    }

    #[test]
    fn deadline_is_bounded_and_does_not_become_success() {
        let scope = TestScope::new(None);
        let mut coordinator = GracefulTerminationCoordinator::new().unwrap();
        let _observer = coordinator
            .begin(
                TerminationCause::InternalTerminateRequest,
                Duration::from_millis(1),
                &scope,
            )
            .unwrap()
            .unwrap();
        let mut fd = libc::pollfd {
            fd: coordinator.timer_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut fd, 1, 1000) }, 1);
        assert!(coordinator.consume_deadline().unwrap());
        assert!(matches!(
            coordinator.deadline_expired(),
            GracefulTerminationOutcome::DeadlineExpired { .. }
        ));
        assert_eq!(scope.requests.load(Ordering::SeqCst), 1);
    }
