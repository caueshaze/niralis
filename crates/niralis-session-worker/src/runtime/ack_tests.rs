#[cfg(test)]
mod pre_started_ack_tests {
    use super::*;

    #[test]
    fn correlated_ack_round_trips_before_started() {
        let (mut launcher, worker) = UnixStream::pair().unwrap();
        let previous = set_supervisor_channel_fd(worker.as_raw_fd());
        let writer = std::thread::spawn(move || {
            niralis_session::write_control_request(
                &mut launcher,
                WorkerControlRequest::PayloadScopeRegistered {
                    worker_id: "worker-test".into(),
                    expected_worker_pid: 42,
                    registration_nonce: "nonce-test".into(),
                },
            )
            .unwrap();
        });
        await_payload_scope_ack(
            "worker-test",
            42,
            "nonce-test",
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        writer.join().unwrap();
        set_supervisor_channel_fd(previous);
    }

    #[test]
    fn divergent_ack_is_rejected() {
        let (mut launcher, worker) = UnixStream::pair().unwrap();
        let previous = set_supervisor_channel_fd(worker.as_raw_fd());
        let writer = std::thread::spawn(move || {
            niralis_session::write_control_request(
                &mut launcher,
                WorkerControlRequest::PayloadScopeRegistered {
                    worker_id: "other-worker".into(),
                    expected_worker_pid: 42,
                    registration_nonce: "nonce-test".into(),
                },
            )
            .unwrap();
        });
        assert_eq!(
            await_payload_scope_ack(
                "worker-test",
                42,
                "nonce-test",
                Instant::now() + Duration::from_secs(1)
            ),
            Err(SessionError::WorkerProtocolFailed)
        );
        writer.join().unwrap();
        set_supervisor_channel_fd(previous);
    }

    #[test]
    fn complete_ack_is_drained_before_hup_is_classified() {
        let (mut launcher, worker) = UnixStream::pair().unwrap();
        let previous = set_supervisor_channel_fd(worker.as_raw_fd());
        niralis_session::write_control_request(
            &mut launcher,
            WorkerControlRequest::PayloadScopeRegistered {
                worker_id: "worker-test".into(),
                expected_worker_pid: 42,
                registration_nonce: "nonce-test".into(),
            },
        )
        .unwrap();
        drop(launcher);
        assert_eq!(
            await_payload_scope_ack(
                "worker-test",
                42,
                "nonce-test",
                Instant::now() + Duration::from_secs(1)
            ),
            Ok(())
        );
        set_supervisor_channel_fd(previous);
    }
}

