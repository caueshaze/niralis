impl FullWorker {
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
        self.expect_after_supervisor_disconnect(cause);
        self.expect_after_supervisor_disconnect("GracefulRequestObserved:count=1");
        self.send_harness_command("AllowPayloadExit");
        self.expect_after_supervisor_disconnect("TimerArmed");
        self.expect_after_supervisor_disconnect("LeaderReaped");
        self.send_harness_command("MakeBoundaryTerminal");
        self.expect_after_supervisor_disconnect("BoundaryCandidate");
        self.expect_after_supervisor_disconnect("BoundaryEmptyProofEstablished:count=1");
        self.expect_after_supervisor_disconnect("BoundaryEmptyProofAccepted");
        self.expect_after_supervisor_disconnect("UnitUnrefAttempted:count=1");
        self.expect_after_supervisor_disconnect("PamCloseStarted");
        self.expect_after_supervisor_disconnect("PamCloseCompleted");
        self.expect_after_supervisor_disconnect("PamDropped");
        let terminal_attempt = self
            .supervisor
            .is_some()
            .then(|| self.acknowledge_terminal_vt_intent());
        self.expect_after_supervisor_disconnect("VtReleased");
        if let Some(attempt_id) = terminal_attempt {
            self.acknowledge_terminal_vt_result(attempt_id);
        }
        self.expect_after_supervisor_disconnect("WorkerReturning");
        let status = self.child.wait().expect("reap full worker fixture");
        assert!(
            status.success(),
            "full worker returned {status:?}; events={:?}",
            self.events
        );
    }

    fn finish_forced(&mut self, expect_leader_sigkill: bool) {
        self.expect("ForcedKillObserved:count=1");
        self.expect("ForcedTerminationRequested:count=1");
        self.expect("ForcedTimerArmed");
        if expect_leader_sigkill {
            self.expect("LeaderReaped");
            self.expect("LeaderKilledBySigkill");
        }
        self.expect("BoundaryEmptyProofEstablished:count=1");
        self.expect("BoundaryEmptyProofAccepted");
        self.expect("UnitUnrefAttempted:count=1");
        self.expect("PamCloseStarted");
        self.expect("PamCloseCompleted");
        self.expect("PamDropped");
        let terminal_attempt = self
            .supervisor
            .is_some()
            .then(|| self.acknowledge_terminal_vt_intent());
        self.expect("VtReleased");
        if let Some(attempt_id) = terminal_attempt {
            self.acknowledge_terminal_vt_result(attempt_id);
        }
        self.expect("WorkerReturning");
        let status = self.child.wait().expect("reap forced full worker fixture");
        assert!(status.success(), "forced worker returned {status:?}; events={:?}", self.events);
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
