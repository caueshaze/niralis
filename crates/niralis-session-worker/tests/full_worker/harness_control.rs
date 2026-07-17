impl FullWorker {
    fn expect_release_ready(&mut self) {
        let envelope = self.read_response();
        assert!(matches!(
            envelope.message,
            WorkerResponse::PayloadScopeReleaseReady { ref worker_id }
                if worker_id == "fixture-worker"
        ));
    }

    fn answer_release(&mut self, recovery: bool) {
        self.expect_release_ready();
        let mut stream = self
            .supervisor
            .take()
            .expect("dedicated supervisor channel remains connected");
        let request = niralis_session::read_control_request(&mut stream)
            .expect("read authenticated release request");
        let (
            worker_id,
            expected_worker_pid,
            registration_nonce,
            release_nonce,
            scope_identity,
            local_cleanup_succeeded,
        ) = match request.message {
            WorkerControlRequest::PayloadScopeReleaseRequested {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                release_nonce,
                scope_identity,
                local_cleanup_succeeded,
            } => (
                worker_id,
                expected_worker_pid,
                registration_nonce,
                release_nonce,
                scope_identity,
                local_cleanup_succeeded,
            ),
            request => panic!("expected release request, got {request:?}"),
        };
        assert_eq!(worker_id, "fixture-worker");
        assert_eq!(expected_worker_pid, self.child.id());
        assert!(scope_identity.validate());
        assert!(local_cleanup_succeeded);
        self.expect("PayloadScopeReleaseRequested:count=1");
        let response = if recovery {
            WorkerControlRequest::PayloadScopeRecoveryRequired {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                release_nonce,
                reason: PayloadScopeRecoveryReason::IdentityMismatch,
            }
        } else {
            WorkerControlRequest::PayloadScopeReleased {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                release_nonce,
            }
        };
        niralis_session::write_control_request(&mut stream, response)
            .expect("send authenticated release result");
        self.supervisor = Some(stream);
    }

    fn read_event(&mut self) -> String {
        let mut bytes = Vec::new();
        let count = self
            .harness
            .read_until(b'\n', &mut bytes)
            .expect("bounded harness event read");
        assert_ne!(
            count, 0,
            "fixture closed harness channel; events={:?}",
            self.events
        );
        assert!(bytes.len() <= 256, "oversized harness frame");
        assert_eq!(bytes.pop(), Some(b'\n'), "unterminated harness frame");
        let event = String::from_utf8(bytes).expect("UTF-8 harness event");
        if let Some(value) = event.strip_prefix("LeaderPid:") {
            self.leader_pid = Some(value.parse().expect("numeric leader pid"));
        }
        self.events.push(event.clone());
        event
    }

    fn expect(&mut self, expected: &str) {
        let event = self.read_event();
        assert_eq!(event, expected, "unexpected harness event sequence");
    }

    fn expect_prefix(&mut self, prefix: &str) -> String {
        let event = self.read_event();
        assert!(
            event.starts_with(prefix),
            "expected prefix {prefix:?}, got {event:?}"
        );
        event
    }

    fn signal(&self, signal: libc::c_int) {
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, signal) },
            0
        );
    }

    fn send_harness_command(&mut self, command: &str) {
        assert!(command.len() <= 63 && !command.as_bytes().contains(&b'\n'));
        let stream = self.harness.get_mut();
        stream
            .write_all(command.as_bytes())
            .expect("write bounded harness command");
        stream.write_all(b"\n").expect("frame harness command");
        stream.flush().expect("flush harness command");
    }

    fn continue_phase(&mut self, phase: &str) {
        self.send_harness_command(&format!("ContinuePhase:{phase}"));
    }

    fn disconnect_supervisor(&mut self) {
        drop(self.supervisor.take());
    }

    fn assert_process_alive(&self, pid: u32) {
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, 0);
    }

    fn expect_session_failed(&mut self) {
        let envelope = self.read_response();
        assert!(matches!(
            envelope.message,
            WorkerResponse::SessionFailed { .. }
        ));
    }

    fn finish_cancelled_launch(&mut self) {
        self.expect("PamCloseStarted");
        self.expect("PamCloseCompleted");
        self.expect("PamDropped");
        self.expect("VtReleased");
        self.expect("WorkerReturning");
        self.expect_session_failed();
        let status = self.child.wait().expect("reap cancelled worker fixture");
        assert_eq!(status.code(), Some(1));
    }

    fn assert_event_absent(&self, prefix: &str) {
        assert!(
            !self.events.iter().any(|event| event.starts_with(prefix)),
            "unexpected event with prefix {prefix:?}: {:?}",
            self.events
        );
    }

    fn finish_cooperative(&mut self, cause: &str) {
        self.expect(cause);
        self.expect("GracefulRequestObserved:count=1");
        self.send_harness_command("AllowPayloadExit");
        self.expect("TimerArmed");
        self.expect("LeaderReaped");
        self.send_harness_command("MakeBoundaryTerminal");
        self.expect("BoundaryCandidate");
        self.expect("BoundaryEmptyProofEstablished:count=1");
        self.expect("BoundaryEmptyProofAccepted");
        self.expect("UnitUnrefAttempted:count=1");
        self.expect("PamCloseStarted");
        self.expect("PamCloseCompleted");
        self.expect("PamDropped");
        self.expect("VtReleased");
        self.expect("WorkerReturning");
        let status = self.child.wait().expect("reap full worker fixture");
        assert!(
            status.success(),
            "full worker returned {status:?}; events={:?}",
            self.events
        );
    }

    fn teardown_non_cooperative(&mut self) {
        let leader = self.leader_pid.expect("real leader pid recorded");
        self.assert_process_alive(self.child.id());
        self.assert_process_alive(leader);
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGKILL) },
            0
        );
        let status = self
            .child
            .wait()
            .expect("reap test fixture after assertions");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    fn teardown_retained_worker(&mut self) {
        self.assert_process_alive(self.child.id());
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGKILL) },
            0
        );
        let status = self.child.wait().expect("reap retained worker fixture");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    fn assert_running_ownership_retained(&self) {
        self.assert_event_absent("TimerArmed");
        self.assert_event_absent("BoundaryEmptyProofAccepted");
        self.assert_event_absent("UnitUnrefAttempted");
        self.assert_event_absent("PamClose");
        self.assert_event_absent("VtReleased");
        self.assert_event_absent("WorkerReturning");
    }
}
