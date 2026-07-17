impl Drop for FullWorker {
    fn drop(&mut self) {
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
fn full_worker_sigterm_non_cooperative_deadline() {
    let mut worker = FullWorker::spawn("non-cooperative");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("TimerArmed");
    worker.expect("DeadlineExpired");
    worker.expect("NeedsEscalation");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    assert!(!worker.events.iter().any(|event| {
        event.starts_with("BoundaryEmptyProof")
            || event.starts_with("UnitUnrefAttempted")
            || event.starts_with("PamClose")
            || event == "VtReleased"
            || event == "WorkerReturning"
    }));
    worker.teardown_non_cooperative();
}

#[test]
fn full_worker_invalidation_before_kill_preserves_pam_vt() {
    let mut worker = FullWorker::spawn("invalidation-before-kill");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.expect("InvocationInvalidatedBeforeKill");
    worker.expect("NeedsEscalation");
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
    worker.expect("NeedsEscalation");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    worker.assert_running_ownership_retained();
    worker.teardown_non_cooperative();
}

#[test]
fn full_worker_replacement_during_proof_enters_recovery() {
    let mut worker = FullWorker::spawn("replacement-during-proof");
    worker.signal(libc::SIGTERM);
    worker.expect("Cause:Sigterm");
    worker.expect("GracefulRequestObserved:count=1");
    worker.send_harness_command("AllowPayloadExit");
    worker.expect("TimerArmed");
    worker.expect("LeaderReaped");
    worker.send_harness_command("MakeBoundaryTerminal");
    worker.expect("BoundaryCandidate");
    worker.expect("InvocationReplacedDuringProof");
    worker.expect("RecoveryRequired");
    worker.expect("OwnershipRetained:Pam,Vt,Pin");
    worker.assert_event_absent("BoundaryEmptyProofAccepted");
    worker.assert_event_absent("UnitUnrefAttempted");
    worker.assert_event_absent("PamClose");
    worker.assert_event_absent("VtReleased");
    worker.assert_event_absent("WorkerReturning");
    worker.teardown_retained_worker();
}

#[test]
fn full_worker_supervisor_disconnect() {
    let mut worker = FullWorker::spawn("cooperative");
    worker.disconnect_supervisor();
    worker.finish_cooperative("Cause:SupervisorDisconnected");
}

#[test]
fn full_worker_signal_then_supervisor_disconnect() {
    let mut worker = FullWorker::spawn("cooperative");
    worker.signal(libc::SIGTERM);
    worker.disconnect_supervisor();
    worker.finish_cooperative("Cause:Sigterm");
}

#[test]
fn full_worker_signal_mask_installed_before_runtime() {
    let mut worker = FullWorker::spawn("cooperative");
    let installed = worker
        .events
        .iter()
        .position(|event| event == "SignalMaskInstalled")
        .unwrap();
    let accepted = worker
        .events
        .iter()
        .position(|event| event == "RequestAccepted")
        .unwrap();
    assert!(installed < accepted);
    worker.signal(libc::SIGTERM);
    worker.finish_cooperative("Cause:Sigterm");
}

#[test]
fn full_worker_payload_signal_mask_restored() {
    let mut worker = FullWorker::spawn("cooperative");
    assert!(worker
        .events
        .iter()
        .any(|event| event == "PayloadSignalMaskRestored"));
    worker.signal(libc::SIGTERM);
    worker.finish_cooperative("Cause:Sigterm");
}

#[test]
fn full_worker_fd_cloexec_hygiene() {
    let mut worker = FullWorker::spawn("cooperative");
    assert!(worker
        .events
        .iter()
        .any(|event| event == "PayloadFdHygieneVerified"));
    assert!(worker.events.iter().any(|event| event == "SignalFdCloexec"));
    assert!(worker
        .events
        .iter()
        .any(|event| event == "SupervisorFdCloexec"));
    assert!(worker.events.iter().any(|event| event == "TimerFdCloexec"));
    worker.signal(libc::SIGTERM);
    worker.finish_cooperative("Cause:Sigterm");
}

#[test]
fn full_worker_cooperative_finalization_order() {
    let mut worker = FullWorker::spawn("cooperative");
    worker.signal(libc::SIGTERM);
    worker.finish_cooperative("Cause:Sigterm");
    let expected = [
        "Cause:Sigterm",
        "GracefulRequestObserved:count=1",
        "LeaderReaped",
        "BoundaryCandidate",
        "BoundaryEmptyProofEstablished:count=1",
        "UnitUnrefAttempted:count=1",
        "PamCloseStarted",
        "PamCloseCompleted",
        "PamDropped",
        "VtReleased",
        "WorkerReturning",
    ];
    let positions: Vec<_> = expected
        .iter()
        .map(|expected| {
            worker
                .events
                .iter()
                .position(|event| event == expected)
                .unwrap()
        })
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

