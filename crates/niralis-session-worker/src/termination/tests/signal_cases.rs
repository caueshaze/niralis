    #[test]
    fn real_process_signals_are_consumed_by_signalfd() {
        for (raw, expected) in [
            (libc::SIGTERM, WorkerTerminationSignal::Sigterm),
            (libc::SIGINT, WorkerTerminationSignal::Sigint),
            (libc::SIGHUP, WorkerTerminationSignal::Sighup),
        ] {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let signals = WorkerSignalFd::install().unwrap();
                unsafe { libc::kill(libc::getpid(), raw) };
                let mut fd = libc::pollfd {
                    fd: signals.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ok = unsafe { libc::poll(&mut fd, 1, 1000) } == 1
                    && signals
                        .read_signal()
                        .unwrap()
                        .and_then(WorkerTerminationSignal::from_raw)
                        == Some(expected);
                std::mem::forget(signals);
                unsafe { libc::_exit(if ok { 0 } else { 1 }) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
