fn shutdown_workers(children: &mut Vec<SupervisedWorker>) {
    for worker in children.iter_mut() {
        if !worker.worker_id.is_empty() {
            if let Ok(mut control) = UnixStream::connect(&worker.control_path) {
                let _ = write_control_request(
                    &mut control,
                    WorkerControlRequest::Terminate {
                        worker_id: worker.worker_id.clone(),
                        expected_worker_pid: worker.child.id(),
                        expected_session_pid: worker.session_pid,
                        expected_session_pgid: worker.session_pgid,
                    },
                );
            }
        }
        let _ = worker
            ._supervisor_channel
            .shutdown(std::net::Shutdown::Both);
    }
    let deadline = Instant::now() + Duration::from_secs(6);
    while !children.is_empty() && Instant::now() < deadline {
        children.retain_mut(|worker| worker.child.try_wait().ok().flatten().is_none());
        if !children.is_empty() {
            thread::sleep(Duration::from_millis(25));
        }
    }
    for worker in children {
        let _ = terminate_group(worker.session_pgid, libc::SIGKILL);
        let _ = worker.child.kill();
        let _ = worker.child.wait();
    }
}

fn request_worker_termination(worker: &mut SupervisedWorker) -> Result<(), SessionError> {
    if worker.worker_id.is_empty() {
        return Err(SessionError::WorkerIoFailed);
    }

    if worker
        .child
        .try_wait()
        .map_err(|_| SessionError::WorkerIoFailed)?
        .is_some()
    {
        return Ok(());
    }

    let mut control = match UnixStream::connect(&worker.control_path) {
        Ok(control) => control,
        Err(_) => {
            return if worker
                .child
                .try_wait()
                .map_err(|_| SessionError::WorkerIoFailed)?
                .is_some()
            {
                Ok(())
            } else {
                Err(SessionError::WorkerIoFailed)
            }
        }
    };

    let result = write_control_request(
        &mut control,
        WorkerControlRequest::Terminate {
            worker_id: worker.worker_id.clone(),
            expected_worker_pid: worker.child.id(),
            expected_session_pid: worker.session_pid,
            expected_session_pgid: worker.session_pgid,
        },
    );

    if result.is_ok() {
        return Ok(());
    }

    if worker
        .child
        .try_wait()
        .map_err(|_| SessionError::WorkerIoFailed)?
        .is_some()
    {
        Ok(())
    } else {
        result
    }
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

