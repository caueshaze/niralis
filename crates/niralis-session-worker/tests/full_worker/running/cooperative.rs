impl Drop for FullWorker {
    fn drop(&mut self) {
        if let Some(member_pid) = self.member_pid {
            let _ = unsafe { libc::kill(member_pid as libc::pid_t, libc::SIGKILL) };
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

trait ExitStatusSignal {
    fn signal(&self) -> Option<i32>;
}

impl ExitStatusSignal for std::process::ExitStatus {
    fn signal(&self) -> Option<i32> {
        std::os::unix::process::ExitStatusExt::signal(self)
    }
}

fn cooperative_signal(signal: libc::c_int, cause: &str) {
    let mut worker = FullWorker::spawn("cooperative");
    worker.signal(signal);
    worker.finish_cooperative(cause);
}

#[test]
fn full_worker_sigterm_cooperative() {
    cooperative_signal(libc::SIGTERM, "Cause:Sigterm");
}

#[test]
fn full_worker_sigint_cooperative() {
    cooperative_signal(libc::SIGINT, "Cause:Sigint");
}

#[test]
fn full_worker_sighup_cooperative() {
    cooperative_signal(libc::SIGHUP, "Cause:Sighup");
}

#[test]
fn full_worker_non_cooperative_payload_is_forced_and_finalized() {
    let mut worker = FullWorker::spawn("non-cooperative");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("TimerArmed");
    worker.expect("DeadlineExpired");
    worker.expect("NeedsEscalation");
    worker.finish_forced(true);
    assert_eq!(
        worker
            .events
            .iter()
            .filter(|event| event.starts_with("ForcedKillObserved"))
            .count(),
        1
    );
}

#[test]
fn full_worker_invalidation_before_kill_preserves_pam_vt() {
    let mut worker = FullWorker::spawn("invalidation-before-kill");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("InvocationInvalidatedBeforeKill");
    worker.expect("InfrastructureFailure");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    worker.assert_running_ownership_retained();
    worker.teardown_non_cooperative();
}

#[test]
fn full_worker_bus_loss_before_kill_preserves_pam_vt() {
    let mut worker = FullWorker::spawn("bus-loss-before-kill");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("SystemBusLostBeforeKill");
    worker.expect("InfrastructureFailure");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    worker.assert_running_ownership_retained();
    worker.teardown_non_cooperative();
}

#[test]
fn full_worker_leader_exit_with_remaining_member_is_forced() {
    let mut worker = FullWorker::spawn("leader-exit-remaining-member");
    worker.expect("LeaderReaped");
    worker.expect("Cause:LeaderExited");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("TimerArmed");
    worker.expect("DeadlineExpired");
    worker.expect("NeedsEscalation");
    worker.finish_forced(false);
}

#[test]
fn full_worker_forced_deadline_preserves_ownership() {
    let mut worker = FullWorker::spawn("forced-deadline");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("TimerArmed");
    worker.expect("DeadlineExpired");
    worker.expect("NeedsEscalation");
    worker.expect("ForcedKillObserved:count=1");
    worker.expect("ForcedTerminationRequested:count=1");
    worker.expect("ForcedTimerArmed");
    worker.expect("ForcedDeadlineExpired");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    worker.assert_event_absent("BoundaryEmptyProofAccepted");
    worker.assert_event_absent("UnitUnrefAttempted");
    worker.assert_event_absent("PamClose");
    worker.assert_event_absent("VtReleased");
    worker.assert_event_absent("WorkerReturning");
    worker.teardown_non_cooperative();
}

#[test]
fn full_worker_replacement_before_forced_kill_preserves_ownership() {
    let mut worker = FullWorker::spawn("replacement-before-forced-kill");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("TimerArmed");
    worker.expect("DeadlineExpired");
    worker.expect("InvocationReplacedBeforeForcedKill");
    worker.expect("RecoveryRequired");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    worker.assert_event_absent("ForcedKillObserved");
    worker.teardown_non_cooperative();
}

#[test]
fn full_worker_bus_loss_after_forced_kill_preserves_ownership_without_retry() {
    let mut worker = FullWorker::spawn("bus-loss-after-forced-kill");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("TimerArmed");
    worker.expect("DeadlineExpired");
    worker.expect("NeedsEscalation");
    worker.expect("ForcedKillObserved:count=1");
    worker.expect("ForcedTerminationRequested:count=1");
    worker.expect("ForcedTimerArmed");
    worker.expect("SystemBusLostAfterForcedKill");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    assert_eq!(
        worker
            .events
            .iter()
            .filter(|event| event.starts_with("ForcedKillObserved"))
            .count(),
        1
    );
    worker.teardown_retained_worker();
}

