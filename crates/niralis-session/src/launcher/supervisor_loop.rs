impl WorkerSupervisor {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || {
            let mut children: Vec<SupervisedWorker> = Vec::new();
            let mut pending: Vec<PendingWorkerLifecycle> = Vec::new();
            loop {
                match receiver.recv_timeout(Duration::from_millis(25)) {
                    Ok(WorkerSupervisorMessage::BeginPending {
                        worker_id,
                        worker_pid,
                        result,
                    }) => {
                        let outcome = if worker_id.is_empty()
                            || pending.iter().any(|entry| entry.worker_id == worker_id)
                        {
                            Err(SessionError::WorkerProtocolFailed)
                        } else {
                            pending.push(PendingWorkerLifecycle {
                                worker_id,
                                worker_pid,
                                payload_scope: None,
                                registration_nonce: None,
                                release_nonce: None,
                                generation: 0,
                                recovery_required: None,
                                terminal_before_started: false,
                            });
                            Ok(())
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::RecordPreparedScope {
                        worker_id,
                        worker_pid,
                        identity,
                        registration_nonce,
                        result,
                    }) => {
                        let outcome = match pending.iter_mut().find(|entry| {
                            entry.worker_id == worker_id && entry.worker_pid == worker_pid
                        }) {
                            Some(entry)
                                if !entry.terminal_before_started
                                    && entry.recovery_required.is_none()
                                    && entry.release_nonce.is_none()
                                    && entry
                                        .payload_scope
                                        .as_ref()
                                        .is_none_or(|existing| existing == &identity) =>
                            {
                                entry.payload_scope = Some(identity);
                                entry.registration_nonce = Some(registration_nonce);
                                entry.generation = entry.generation.wrapping_add(1);
                                Ok(())
                            }
                            _ => Err(SessionError::WorkerProtocolFailed),
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::BeginRelease { request, result }) => {
                        let outcome = match pending.iter_mut().find(|entry| {
                            entry.worker_id == request.worker_id
                                && entry.worker_pid == request.worker_pid
                        }) {
                            Some(entry)
                                if !entry.terminal_before_started
                                    && entry.recovery_required.is_none()
                                    && entry.payload_scope.as_ref() == Some(&request.identity)
                                    && entry.registration_nonce.as_deref()
                                        == Some(&request.registration_nonce)
                                    && entry
                                        .release_nonce
                                        .as_ref()
                                        .is_none_or(|nonce| nonce == &request.release_nonce) =>
                            {
                                entry.release_nonce = Some(request.release_nonce.clone());
                                entry.generation = entry.generation.wrapping_add(1);
                                Ok(ReleaseToken {
                                    worker_id: request.worker_id,
                                    worker_pid: request.worker_pid,
                                    registration_nonce: request.registration_nonce,
                                    release_nonce: request.release_nonce,
                                    identity: request.identity,
                                    generation: entry.generation,
                                })
                            }
                            _ => Err(SessionError::WorkerProtocolFailed),
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::CompleteRelease {
                        token,
                        verification,
                        result,
                    }) => {
                        let index = pending.iter().position(|entry| {
                            entry.worker_id == token.worker_id
                                && entry.worker_pid == token.worker_pid
                                && entry.generation == token.generation
                                && entry.payload_scope.as_ref() == Some(&token.identity)
                                && entry.registration_nonce.as_deref()
                                    == Some(&token.registration_nonce)
                                && entry.release_nonce.as_deref() == Some(&token.release_nonce)
                        });
                        let outcome = match (index, verification) {
                            (Some(index), crate::ScopeReleaseVerification::Released) => {
                                pending.swap_remove(index);
                                Ok(())
                            }
                            (
                                Some(index),
                                crate::ScopeReleaseVerification::RecoveryRequired(reason),
                            ) => {
                                pending[index].recovery_required = Some(reason);
                                pending[index].terminal_before_started = true;
                                Ok(())
                            }
                            _ => Err(SessionError::WorkerProtocolFailed),
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::AbortPending { worker_id }) => {
                        if let Some(index) = pending
                            .iter()
                            .position(|entry| entry.worker_id == worker_id)
                        {
                            if pending[index].payload_scope.is_some() {
                                pending[index].terminal_before_started = true;
                                let reason = pending[index].recovery_required.get_or_insert(
                                    crate::PayloadScopeRecoveryReason::VerificationUnavailable,
                                );
                                tracing::warn!(?reason, worker_id, "worker died with acknowledged payload scope still registered; recovery required");
                            } else {
                                pending.swap_remove(index);
                            }
                        }
                    }
                    Ok(WorkerSupervisorMessage::Register {
                        runtime_id,
                        child,
                        supervisor_channel,
                        session,
                        session_pid,
                        session_pgid,
                        worker_id,
                        logind_session_id,
                        payload_scope,
                        control_path,
                        control_dir,
                        result,
                    }) => {
                        let index = pending.iter().position(|entry| {
                            entry.worker_id == worker_id
                                && entry.worker_pid == child.id()
                                && entry.payload_scope.as_ref() == Some(&payload_scope)
                                && entry.release_nonce.is_none()
                                && entry.recovery_required.is_none()
                                && !entry.terminal_before_started
                        });
                        if let Some(index) = index {
                            pending.swap_remove(index);
                            children.push(SupervisedWorker {
                                ownership: RuntimeOwnership {
                                    runtime_id,
                                    logind_session_id,
                                    payload_scope,
                                },
                                child,
                                _supervisor_channel: supervisor_channel,
                                session,
                                session_pid,
                                session_pgid,
                                worker_id,
                                control_path,
                                _control_dir: control_dir,
                            });
                            let _ = result.send(Ok(()));
                        } else {
                            let mut child = child;
                            let _ = child.kill();
                            let _ = child.wait();
                            let _ = result.send(Err(SessionError::WorkerProtocolFailed));
                        }
                    }
                    Ok(WorkerSupervisorMessage::Terminate {
                        session,
                        runtime_id,
                        result,
                    }) => {
                        let outcome = if let Some(worker) = children.iter_mut().find(|worker| {
                            runtime_id.as_ref().map_or(worker.session == session, |id| {
                                worker.ownership.runtime_id == *id
                            })
                        }) {
                            request_worker_termination(worker)
                        } else {
                            Ok(())
                        };
                        let _ = result.send(outcome);
                    }
                    Ok(WorkerSupervisorMessage::Shutdown)
                    | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        shutdown_workers(&mut children);
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                let mut index = 0;
                while index < children.len() {
                    match children[index].child.try_wait() {
                        Ok(Some(status)) => {
                            debug!(?status, username = %children[index].session.username, session_pid = children[index].session_pid, logind_session_id = %children[index].ownership.logind_session_id.as_str(), "session worker exited and was reaped; runtime/logind ownership removed");
                            children.swap_remove(index);
                        }
                        Ok(None) => index += 1,
                        Err(error) => {
                            debug!(?error, "failed to inspect session worker");
                            index += 1;
                        }
                    }
                }
            }
        });
        Self {
            sender,
            join: Mutex::new(Some(join)),
        }
    }

}
