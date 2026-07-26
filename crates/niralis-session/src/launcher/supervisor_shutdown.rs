fn shutdown_workers(children: &mut Vec<SupervisedWorker>) {
    for worker in children.iter_mut() {
        if !worker.worker_id.is_empty() {
            let _ = send_terminate_request(worker);
        }
        let _ = worker
            .supervisor_channel
            .shutdown(std::net::Shutdown::Both);
    }
    let deadline = Instant::now() + Duration::from_secs(6);
    while !children.is_empty() && Instant::now() < deadline {
        children.retain_mut(|worker| {
            worker
                .child
                .lock()
                .ok()
                .and_then(|mut child| child.try_wait().ok())
                .flatten()
                .is_none()
        });
        if !children.is_empty() {
            thread::sleep(Duration::from_millis(25));
        }
    }
    for worker in children {
        kill_shared_worker(&worker.child);
    }
}

fn request_worker_termination(worker: &mut SupervisedWorker) -> Result<(), SessionError> {
    if worker.worker_id.is_empty() {
        return Err(SessionError::WorkerIoFailed);
    }

    if worker
        .child
        .lock()
        .map_err(|_| SessionError::WorkerIoFailed)?
        .try_wait()
        .map_err(|_| SessionError::WorkerIoFailed)?
        .is_some()
    {
        return Ok(());
    }

    let result = send_terminate_request(worker);

    if result.is_ok() {
        return Ok(());
    }

    if worker
        .child
        .lock()
        .map_err(|_| SessionError::WorkerIoFailed)?
        .try_wait()
        .map_err(|_| SessionError::WorkerIoFailed)?
        .is_some()
    {
        Ok(())
    } else {
        result
    }
}

fn send_terminate_request(worker: &mut SupervisedWorker) -> Result<(), SessionError> {
    #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    if let Some(transport) = worker.fixture_supervisor_transport.as_mut() {
        return transport.send_request(WorkerControlRequest::Terminate {
            worker_id: worker.worker_id.clone(),
            expected_worker_pid: worker.record.worker_pid,
            expected_session_pid: worker.session_pid,
            expected_session_pgid: worker.session_pgid,
        });
    }

    #[cfg(any(test, feature = "integration-test-control", feature = "supervisor-test-fixtures"))]
    if worker.fixture_inherited_supervisor_control {
        return write_control_request(
            &mut worker.supervisor_channel,
            WorkerControlRequest::Terminate {
                worker_id: worker.worker_id.clone(),
                expected_worker_pid: worker.record.worker_pid,
                expected_session_pid: worker.session_pid,
                expected_session_pgid: worker.session_pgid,
            },
        );
    }

    let mut control = UnixStream::connect(&worker.control_path).map_err(|_| SessionError::WorkerIoFailed)?;
    write_control_request(
        &mut control,
        WorkerControlRequest::Terminate {
            worker_id: worker.worker_id.clone(),
            expected_worker_pid: worker.record.worker_pid,
            expected_session_pid: worker.session_pid,
            expected_session_pgid: worker.session_pgid,
        },
    )
}

impl Drop for WorkerSupervisor {
    fn drop(&mut self) {
        let _ = self.sender.send(WorkerSupervisorMessage::Shutdown);
        if let Ok(mut join) = self.join.lock() {
            if let Some(handle) = join.take() {
                let _ = handle.join();
            }
        }
    }
}
