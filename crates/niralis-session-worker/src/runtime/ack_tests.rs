#[cfg(test)]
mod pre_started_ack_tests {
    use super::*;

    fn transaction() -> niralis_session::WorkerTransactionIdentity {
        niralis_session::WorkerTransactionIdentity {
            transaction_id: "worker-test".into(),
            admission_attempt_id: 1,
            lifecycle_id: "worker-test".into(),
            seat: "seat0".into(),
            seat_generation: 1,
            stage: "scope_prepared".into(),
        }
    }

    fn read_ack(
        stream: &mut impl std::io::Read,
        worker_id: &str,
        pid: u32,
        nonce: &str,
        transaction: &niralis_session::WorkerTransactionIdentity,
    ) -> Result<(), SessionError> {
        let envelope = niralis_session::read_control_request(stream)?;
        match envelope.message {
            WorkerControlRequest::PayloadScopeRegistered {
                transaction: ack,
                worker_id: actual_worker_id,
                expected_worker_pid,
                registration_nonce,
            } if envelope.version == WORKER_CONTROL_PROTOCOL_VERSION
                && actual_worker_id == worker_id
                && expected_worker_pid == pid
                && registration_nonce == nonce
                && ack.matches_worker(transaction, "scope_registered", 1) => Ok(()),
            _ => Err(SessionError::WorkerProtocolFailed),
        }
    }

    #[test]
    fn correlated_ack_round_trips_before_started() {
        let transaction = transaction();
        let ack_transaction = transaction.clone();
        let mut bytes = Vec::new();
        niralis_session::write_control_request(&mut bytes, WorkerControlRequest::PayloadScopeRegistered {
            transaction: niralis_session::ControlTransactionIdentity::from_worker(&ack_transaction, "scope_registered", 1),
            worker_id: "worker-test".into(), expected_worker_pid: 42, registration_nonce: "nonce-test".into(),
        }).unwrap();
        let mut worker = std::io::Cursor::new(bytes);
        read_ack(
            &mut worker,
            "worker-test",
            42,
            "nonce-test",
            &transaction,
        )
        .unwrap();
    }

    #[test]
    fn divergent_ack_is_rejected() {
        let transaction = transaction();
        let ack_transaction = transaction.clone();
        let mut bytes = Vec::new();
        niralis_session::write_control_request(&mut bytes, WorkerControlRequest::PayloadScopeRegistered {
            transaction: niralis_session::ControlTransactionIdentity::from_worker(&ack_transaction, "scope_registered", 1),
            worker_id: "other-worker".into(), expected_worker_pid: 42, registration_nonce: "nonce-test".into(),
        }).unwrap();
        let mut worker = std::io::Cursor::new(bytes);
        assert_eq!(
            read_ack(
                &mut worker,
                "worker-test",
                42,
                "nonce-test",
                &transaction
            ),
            Err(SessionError::WorkerProtocolFailed)
        );
    }

    #[test]
    fn complete_ack_is_drained_before_hup_is_classified() {
        let transaction = transaction();
        let mut bytes = Vec::new();
        niralis_session::write_control_request(
            &mut bytes,
            WorkerControlRequest::PayloadScopeRegistered {
                transaction: niralis_session::ControlTransactionIdentity::from_worker(&transaction, "scope_registered", 1),
                worker_id: "worker-test".into(),
                expected_worker_pid: 42,
                registration_nonce: "nonce-test".into(),
            },
        )
        .unwrap();
        let mut worker = std::io::Cursor::new(bytes);
        assert_eq!(
            read_ack(
                &mut worker,
                "worker-test",
                42,
                "nonce-test",
                &transaction
            ),
            Ok(())
        );
    }
}
