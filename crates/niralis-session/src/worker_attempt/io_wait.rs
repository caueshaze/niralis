
fn spawn_reader(
    stdout: ChildStdout,
) -> (
    JoinHandle<()>,
    Receiver<Result<WorkerEnvelope<WorkerResponse>, SessionError>>,
) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut stdout = stdout;
        loop {
            let event = read_envelope::<WorkerResponse, _>(&mut stdout);
            let terminal = event.is_err()
                || matches!(
                    event.as_ref().map(|value| &value.message),
                    Ok(WorkerResponse::Started { .. })
                        | Ok(WorkerResponse::Ready { .. })
                        | Ok(WorkerResponse::AuthenticationFailed)
                        | Ok(WorkerResponse::SessionFailed { .. })
                        | Ok(WorkerResponse::Rejected { .. })
                );
            if sender.send(event).is_err() || terminal {
                break;
            }
        }
    });
    (handle, receiver)
}

fn wait_thread_result<T>(
    receiver: &Receiver<Result<T, SessionError>>,
    deadline: Instant,
    child: &Arc<Mutex<Child>>,
) -> Result<T, SessionError> {
    let timeout = match deadline.checked_duration_since(Instant::now()) {
        Some(timeout) => timeout,
        None => {
            kill_and_reap(child);
            return Err(SessionError::WorkerTimedOut);
        }
    };

    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            kill_and_reap(child);
            Err(SessionError::WorkerTimedOut)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = child
                .lock()
                .map_err(|_| SessionError::WorkerIoFailed)
                .and_then(|mut child| reap_child(&mut child));
            Err(SessionError::WorkerIoFailed)
        }
    }
}

fn wait_for_exit(child: &Arc<Mutex<Child>>, deadline: Instant) -> Result<ExitStatus, SessionError> {
    loop {
        if let Some(status) = child
            .lock()
            .map_err(|_| SessionError::WorkerIoFailed)?
            .try_wait()
            .map_err(|_| SessionError::WorkerIoFailed)?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            kill_and_reap(child);
            return Err(SessionError::WorkerTimedOut);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn kill_and_reap(child: &Arc<Mutex<Child>>) {
    let Ok(mut child) = child.lock() else {
        return;
    };
    if let Ok(Some(_)) = child.try_wait() {
        return;
    }

    let _ = child.kill();
    let _ = reap_child(&mut child);
}

fn reap_child(child: &mut Child) -> Result<(), SessionError> {
    child
        .wait()
        .map(|_| ())
        .map_err(|_| SessionError::WorkerIoFailed)
}
