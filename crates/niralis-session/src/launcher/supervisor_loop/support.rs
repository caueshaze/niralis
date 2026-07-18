use super::*;

pub(crate) fn registration_nonce(record: &SupervisorSessionRecoveryRecord) -> Option<&str> {
    match &record.state {
        SupervisorRecoveryState::PayloadPrepared {
            registration_nonce, ..
        }
        | SupervisorRecoveryState::PayloadRegistered {
            registration_nonce, ..
        } => Some(registration_nonce),
        _ => None,
    }
}

pub(crate) fn mark_worker_exited_unexpectedly(
    record: &mut SupervisorSessionRecoveryRecord,
    status: ExitStatus,
) -> WorkerExitClassification {
    let classification = classify_worker_exit(record, status);
    let state = record.take_state_for_transition();
    record.state = match state {
        SupervisorRecoveryState::PayloadPrepared { payload, .. }
        | SupervisorRecoveryState::PayloadRegistered { payload, .. }
        | SupervisorRecoveryState::PayloadReleased { payload }
        | SupervisorRecoveryState::Started { payload, .. }
        | SupervisorRecoveryState::EmergencyRecovery { payload, .. } => {
            SupervisorRecoveryState::WorkerExitedUnexpectedly {
                payload,
                classification,
            }
        }
        state => state,
    };
    classification
}

pub(crate) fn record_runtime_id(
    record: &SupervisorSessionRecoveryRecord,
) -> Option<&RuntimeSessionId> {
    match &record.state {
        SupervisorRecoveryState::Started { runtime_id, .. } => Some(runtime_id),
        _ => None,
    }
}

pub(crate) fn finalize_expected_prestarted_exit(
    record: &mut SupervisorSessionRecoveryRecord,
    status: ExitStatus,
    provider: &dyn SupervisorRecoveryProvider,
) -> Result<(), SupervisorRecoveryError> {
    let SupervisorRecoveryState::PayloadReleased { payload } = &mut record.state else {
        return Err(SupervisorRecoveryError::InvalidRecord);
    };
    let _proof = payload.boundary.verify_empty(status)?;
    if !provider.confirm_logind_absent(&payload.logind)? {
        return Err(SupervisorRecoveryError::LogindIdentityChanged);
    }
    payload.boundary.release()
}

pub(crate) fn finalize_clean_worker_exit(
    record: &mut SupervisorSessionRecoveryRecord,
    status: ExitStatus,
    provider: &dyn SupervisorRecoveryProvider,
) -> Result<(), SupervisorRecoveryError> {
    if !status.success() {
        return Err(SupervisorRecoveryError::InvalidRecord);
    }
    let SupervisorRecoveryState::Started { payload, .. } = &mut record.state else {
        return Err(SupervisorRecoveryError::InvalidRecord);
    };
    let _proof = payload.boundary.verify_empty(status)?;
    if !provider.confirm_logind_absent(&payload.logind)? {
        return Err(SupervisorRecoveryError::LogindIdentityChanged);
    }
    payload.boundary.release()
}

pub(crate) fn reap_pending_worker(child: &Arc<Mutex<Child>>) -> Result<ExitStatus, SessionError> {
    let mut child = child.lock().map_err(|_| SessionError::WorkerIoFailed)?;
    if let Some(status) = child.try_wait().map_err(|_| SessionError::WorkerIoFailed)? {
        return Ok(status);
    }
    child.kill().map_err(|_| SessionError::WorkerIoFailed)?;
    child.wait().map_err(|_| SessionError::WorkerIoFailed)
}

pub(crate) fn kill_shared_worker(child: &Arc<Mutex<Child>>) {
    if let Ok(mut child) = child.lock() {
        let _ = child.kill();
        let _ = child.wait();
    }
}
