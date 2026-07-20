use super::*;
use std::thread;

pub(super) fn spawn_running_control_reader(
    mut stream: UnixStream,
    sender: mpsc::Sender<WorkerSupervisorMessage>,
) {
    thread::spawn(move || loop {
        let Ok(envelope) = crate::read_control_request(&mut stream) else {
            return;
        };
        if envelope.version != crate::WORKER_CONTROL_PROTOCOL_VERSION {
            return;
        }
        match envelope.message {
            crate::WorkerControlRequest::TerminalVtCleanupIntent {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                scope_identity,
            } => {
                let (result, response) = mpsc::channel();
                if sender
                    .send(WorkerSupervisorMessage::TerminalVtIntent {
                        worker_id: worker_id.clone(),
                        worker_pid: expected_worker_pid,
                        registration_nonce: registration_nonce.clone(),
                        identity: scope_identity,
                        result,
                    })
                    .is_err()
                {
                    return;
                }
                let Ok(Ok(attempt_id)) = response.recv() else {
                    return;
                };
                if crate::write_control_request(
                    &mut stream,
                    crate::WorkerControlRequest::TerminalVtCleanupIntentAcknowledged {
                        worker_id,
                        expected_worker_pid,
                        registration_nonce,
                        attempt_id,
                    },
                )
                .is_err()
                {
                    return;
                }
            }
            crate::WorkerControlRequest::TerminalVtCleanupResult {
                worker_id,
                expected_worker_pid,
                registration_nonce,
                attempt_id,
                result,
            } => {
                let (acknowledged, response) = mpsc::channel();
                if sender
                    .send(WorkerSupervisorMessage::TerminalVtResult {
                        worker_id: worker_id.clone(),
                        worker_pid: expected_worker_pid,
                        registration_nonce: registration_nonce.clone(),
                        attempt_id,
                        result,
                        acknowledged,
                    })
                    .is_err()
                {
                    return;
                }
                let Ok(Ok(())) = response.recv() else {
                    return;
                };
                let _ = crate::write_control_request(
                    &mut stream,
                    crate::WorkerControlRequest::TerminalVtCleanupResultAcknowledged {
                        worker_id,
                        expected_worker_pid,
                        registration_nonce,
                        attempt_id,
                    },
                );
                return;
            }
            _ => return,
        }
    });
}
