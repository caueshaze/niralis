impl SupervisorLoopState {
    pub(super) fn finish_exited_worker(&mut self, index: usize, status: ExitStatus) {
        let mut worker = self.children.swap_remove(index);
        if worker.terminal_vt_reported_busy {
            info!(worker_id = %worker.worker_id, "worker reported durable VT EBUSY; preserving quarantine without emergency recovery");
            let _ = self.admission.enter_quarantine_from_running(
                worker.admission,
                EmergencyRecoveryStage::VtRecovery,
                SupervisorRecoveryError::VtDisallocateBusy,
            );
            self.quarantined.push(worker.record);
            return;
        }
        if status.success()
            && finalize_clean_worker_exit(
                &mut worker.record,
                status,
                self.recovery_provider.as_ref(),
            )
            .is_ok()
            && self
                .resolve_clean_worker_record(&worker.record.lifecycle_id)
                .is_ok()
        {
            debug!(?status, username = %worker.session.username, session_pid = worker.session_pid, "session worker exited and was reaped after verified clean finalization");
            let _ = self
                .admission
                .release_running_after_a3_finalization(worker.admission);
            return;
        }
        warn!(worker_pid = worker.record.worker_pid, status = %exit_status_label(status), phase = worker.record.phase_name(), session = %worker.record.session_name, username = %worker.record.requested_username, "session worker exited unexpectedly");
        let classification = mark_worker_exited_unexpectedly(&mut worker.record, status);
        let _ = self.persist_transition(&worker.record.lifecycle_id, "worker_exited_unexpectedly");
        let recovery_receipt = match self.admission.enter_recovery(
            worker.admission,
            worker.record.phase_name(),
            classification,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                warn!(?error, "running seat receipt rejected during recovery");
                return;
            }
        };
        match SupervisorEmergencyRecoveryCoordinator::new(self.recovery_provider.as_ref())
            .recover(&mut worker.record, status)
        {
            outcome @ SupervisorEmergencyRecoveryOutcome::Recovered { .. } => {
                worker.record.state = SupervisorRecoveryState::Recovered { outcome };
                let _ = self
                    .admission
                    .release_after_a3_finalization(recovery_receipt);
            }
            SupervisorEmergencyRecoveryOutcome::Quarantined { stage, reason } => {
                if matches!(reason, SupervisorRecoveryError::VtDisallocateBusy) {
                    let _ = self.persist_transition(
                        &worker.record.lifecycle_id,
                        "vt_disallocate_failed_busy",
                    );
                }
                worker.record.quarantine(stage, reason.clone());
                let _ = self.admission.enter_quarantine_from_recovery(
                    recovery_receipt,
                    stage,
                    reason,
                );
                self.quarantined.push(worker.record);
            }
        }
    }
}
