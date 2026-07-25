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

    fn acknowledge_terminal_vt_intent(&mut self) -> u64 {
        let mut stream = self
            .supervisor
            .take()
            .expect("dedicated supervisor channel remains connected");
        let request = niralis_session::read_control_request(&mut stream)
            .expect("read terminal VT cleanup intent");
        let (worker_id, expected_worker_pid, registration_nonce, scope_identity) =
            match request.message {
                WorkerControlRequest::TerminalVtCleanupIntent {
                    worker_id,
                    expected_worker_pid,
                    registration_nonce,
                    scope_identity,
                } => (worker_id, expected_worker_pid, registration_nonce, scope_identity),
                request => panic!("expected terminal VT cleanup intent, got {request:?}"),
            };
        assert_eq!(request.version, niralis_session::WORKER_CONTROL_PROTOCOL_VERSION);
        assert_eq!(worker_id, "fixture-worker");
        assert_eq!(expected_worker_pid, self.child.id());
        assert!(scope_identity.validate());
        let attempt_id = 1;
        niralis_session::write_control_request(
            &mut stream,
            WorkerControlRequest::TerminalVtCleanupIntentAcknowledged {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                attempt_id,
            },
        )
        .expect("acknowledge terminal VT cleanup intent");
        self.supervisor = Some(stream);
        attempt_id
    }

    fn acknowledge_terminal_vt_result(&mut self, expected_attempt_id: u64) {
        let mut stream = self
            .supervisor
            .take()
            .expect("dedicated supervisor channel remains connected");
        let request = niralis_session::read_control_request(&mut stream)
            .expect("read terminal VT cleanup result");
        let (worker_id, expected_worker_pid, registration_nonce, attempt_id, result) =
            match request.message {
                WorkerControlRequest::TerminalVtCleanupResult {
                    worker_id,
                    expected_worker_pid,
                    registration_nonce,
                    attempt_id,
                    result,
                } => (
                    worker_id,
                    expected_worker_pid,
                    registration_nonce,
                    attempt_id,
                    result,
                ),
                request => panic!("expected terminal VT cleanup result, got {request:?}"),
            };
        assert_eq!(request.version, niralis_session::WORKER_CONTROL_PROTOCOL_VERSION);
        assert_eq!(worker_id, "fixture-worker");
        assert_eq!(expected_worker_pid, self.child.id());
        assert_eq!(attempt_id, expected_attempt_id);
        assert_eq!(result, niralis_session::TerminalVtCleanupResult::Released);
        niralis_session::write_control_request(
            &mut stream,
            WorkerControlRequest::TerminalVtCleanupResultAcknowledged {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                attempt_id,
            },
        )
        .expect("acknowledge terminal VT cleanup result");
        self.supervisor = Some(stream);
    }

}
