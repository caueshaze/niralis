struct PendingSupervisorGuard {
    supervisor: Arc<WorkerSupervisor>,
    transaction: Option<login_transaction::PendingLaunchTransaction>,
    expected_clean: bool,
    worker_exit_status: Option<ExitStatus>,
}

struct SeatReservationGuard {
    supervisor: Arc<WorkerSupervisor>,
    lease: Option<supervisor_loop::admission::AdmissionLease>,
}

impl SeatReservationGuard {
    fn consume(&mut self) {
        self.lease = None;
    }
}

impl Drop for SeatReservationGuard {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            self.supervisor.cancel_admission(
                supervisor_loop::admission::AdmissionRollbackLease::Reserved(lease),
            );
        }
    }
}

impl Drop for PendingSupervisorGuard {
    fn drop(&mut self) {
        if let Some(mut transaction) = self.transaction.take() {
            let Ok(lease) = transaction.pending_lease() else {
                return;
            };
            let _ = self.supervisor.abort_pending(
                lease,
                self.expected_clean,
                self.worker_exit_status,
            );
        }
    }
}

impl PendingSupervisorGuard {
    fn mark_expected_clean(&mut self, status: ExitStatus) {
        self.expected_clean = true;
        self.worker_exit_status = Some(status);
    }

    fn complete(mut self) -> Result<(), SessionError> {
        if let Some(mut transaction) = self.transaction.take() {
            let lease = transaction.pending_lease()?;
            self.supervisor.abort_pending(
                lease,
                self.expected_clean,
                self.worker_exit_status,
            )?;
        }
        Ok(())
    }

    fn take_transaction(&mut self) -> login_transaction::PendingLaunchTransaction {
        self.transaction
            .take()
            .expect("pending guard owns login transaction")
    }
}
