fn assert_no_post_cancel_launch(worker: &FullWorker) {
    worker.assert_event_absent("CommitExecCalled");
    worker.assert_event_absent("Running");
}

fn run_barrier_a() {
    let mut worker = FullWorker::spawn_barrier("barrier-a");
    worker.expect_preparing();
    worker.expect("PhaseReached:PendingHandoffBeforeScope");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("PendingHandoffBeforeScope");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.finish_cancelled_launch();
    worker.assert_event_absent("ScopePrepared");
    worker.assert_event_absent("PinAcquired");
    worker.assert_event_absent("PayloadScopePreparedSent");
    worker.assert_event_absent("PayloadScopeReleaseRequested");
    assert_no_post_cancel_launch(&worker);
}

fn reach_barrier_b(mode: &str) -> FullWorker {
    let mut worker = FullWorker::spawn_barrier(mode);
    worker.expect_preparing();
    worker.expect("ScopePrepared");
    worker.expect("PinAcquired");
    worker.expect("PayloadScopePreparedSent");
    worker.expect("PhaseReached:ScopePinnedBeforeAck");
    let _ = worker.expect_prepared();
    worker
}

fn run_barrier_b() {
    let mut worker = reach_barrier_b("barrier-b");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("ScopePinnedBeforeAck");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.answer_release(false);
    worker.expect("PayloadScopeReleasedReceived");
    worker.expect("UnitUnrefAttempted:count=1");
    worker.finish_cancelled_launch();
    worker.assert_event_absent("PayloadScopeAcknowledged");
    assert_no_post_cancel_launch(&worker);
}

fn reach_barrier_c(mode: &str) -> FullWorker {
    let mut worker = FullWorker::spawn_barrier(mode);
    worker.expect_preparing();
    worker.expect("ScopePrepared");
    worker.expect("PinAcquired");
    worker.expect("PayloadScopePreparedSent");
    let (registration_nonce, _) = worker.expect_prepared();
    worker.acknowledge_scope(&registration_nonce);
    worker.expect("PayloadScopeAcknowledged");
    worker.expect("PhaseReached:AckReceivedBeforeCommitExec");
    worker
}

fn run_barrier_c_released(duplicate_signal: bool) {
    let mut worker = reach_barrier_c("barrier-c-released");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("AckReceivedBeforeCommitExec");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    if duplicate_signal {
        worker.signal(libc::SIGHUP);
    }
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.answer_release(false);
    worker.expect("PayloadScopeReleasedReceived");
    worker.expect("UnitUnrefAttempted:count=1");
    worker.finish_cancelled_launch();
    assert_no_post_cancel_launch(&worker);
    assert_eq!(
        worker
            .events
            .iter()
            .filter(|event| event.starts_with("ProbeAbortRequested"))
            .count(),
        1
    );
    assert_eq!(
        worker
            .events
            .iter()
            .filter(|event| event.starts_with("LaunchCancellationSignal"))
            .count(),
        1
    );
}
#[test]
fn full_worker_signal_before_scope_prevents_scope_and_commit() {
    run_barrier_a();
}

#[test]
fn full_worker_signal_after_pin_before_ack_prevents_commit() {
    run_barrier_b();
}

#[test]
fn full_worker_signal_after_ack_before_commit_requests_release() {
    run_barrier_c_released(false);
}

#[test]
fn full_worker_recovery_after_ack_before_commit_preserves_identity() {
    let mut worker = reach_barrier_c("barrier-c-recovery");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("AckReceivedBeforeCommitExec");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.answer_release(true);
    worker.expect("PayloadScopeRecoveryRequiredReceived");
    worker.expect("PreStartedRecoveryHeld");
    worker.assert_process_alive(worker.child.id());
    worker.assert_event_absent("UnitUnrefAttempted");
    worker.assert_event_absent("PamClose");
    worker.assert_event_absent("VtReleased");
    worker.assert_event_absent("WorkerReturning");
    assert_no_post_cancel_launch(&worker);
}

#[test]
fn full_worker_duplicate_signals_before_commit_are_idempotent() {
    run_barrier_c_released(true);
}

#[test]
fn full_worker_precommit_disappearance_releases_all_ownership() {
    let mut worker = reach_barrier_c("barrier-c-disappearance");
    worker.signal(libc::SIGTERM);
    worker.continue_phase("AckReceivedBeforeCommitExec");
    worker.expect("LaunchCancellationSignal:SIGTERM");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("OriginalCgroupAbsent");
    worker.expect("CleanupResolveByInvocation:count=1");
    worker.expect("CleanupPropertiesValidated:count=1");
    worker.expect("CleanupResolveByInvocation:count=2");
    worker.expect("CleanupPropertiesValidated:count=2");
    worker.expect("PreCommitDisappearanceProofEstablished");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.answer_release(false);
    worker.expect("PayloadScopeReleasedReceived");
    worker.expect("UnitUnrefAttempted:count=1");
    worker.finish_cancelled_launch();
    assert_no_post_cancel_launch(&worker);
}
