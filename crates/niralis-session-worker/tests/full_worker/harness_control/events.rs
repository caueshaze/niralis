impl FullWorker {
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
        if let Some(value) = event.strip_prefix("BoundaryMemberPid:") {
            self.member_pid = Some(value.parse().expect("numeric member pid"));
        }
        self.events.push(event.clone());
        event
    }

    fn expect(&mut self, expected: &str) {
        let event = self.read_event();
        assert_eq!(event, expected, "unexpected harness event sequence");
    }

    fn expect_after_supervisor_disconnect(&mut self, expected: &str) {
        loop {
            let event = self.read_event();
            if event == "SupervisorDisconnectedObserved" {
                continue;
            }
            assert_eq!(event, expected, "unexpected harness event sequence");
            return;
        }
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

}
