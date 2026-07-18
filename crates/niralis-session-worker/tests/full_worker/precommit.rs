#[test]
fn real_launcher_stdin_eof_is_benign_and_dedicated_ack_allows_commit() {
    let mut launcher = WorkerSessionLauncher::new(
        env!("CARGO_BIN_EXE_fixture-full-worker").into(),
        "/fixture/session-child".into(),
        "/fixture/session-probe".into(),
        HARNESS_TIMEOUT,
        vec![(
            "NIRALIS_FULL_WORKER_FIXTURE_MODE".into(),
            "launcher-channel".into(),
        )],
    )
    .unwrap();
    launcher.use_supervisor_test_fixture_for_test();
    let request = SessionRequest {
        username: "fixture-user".into(),
        session: SessionInfo {
            id: "niri".into(),
            name: "Niri".into(),
            kind: SessionKind::Wayland,
        },
    };
    let plan = SessionExecPlan {
        source_path: b"/fixture.desktop".to_vec(),
        executable: b"/bin/true".to_vec(),
        argv: vec![b"true".to_vec()],
    };
    let (started, _runtime_id) = launcher
        .start_pam_session_for_test(
            request.clone(),
            plan,
            "niralis-fixture".into(),
            WorkerSecret::new("fixture-secret".into()),
        )
        .unwrap();
    assert_eq!(started.username, request.username);
    assert_eq!(started.session, request.session);
}

#[test]
fn full_worker_supervisor_disconnect_while_waiting_for_ack() {
    let mut worker = reach_barrier_b("barrier-b");
    worker.disconnect_supervisor();
    worker.continue_phase("ScopePinnedBeforeAck");
    worker.expect("LaunchSupervisorDisconnected");
    worker.expect("ProbeAbortRequested:count=1");
    worker.expect("ProbeReaped:count=1");
    worker.expect("ScopeCleanupRequested:count=1");
    worker.expect("PinHeldAfterScopeCleanup");
    worker.expect_release_ready();
    worker.expect("PayloadScopeRecoveryRequiredReceived");
    worker.expect("PreStartedRecoveryHeld");
    worker.assert_process_alive(worker.child.id());
    worker.assert_event_absent("UnitUnrefAttempted");
    assert_no_post_cancel_launch(&worker);
}

#[test]
fn phase_gate_is_not_runtime_selectable() {
    let cargo = include_str!("../../Cargo.toml");
    let production_main = include_str!("../../src/main.rs");
    let runtime = concat!(
        include_str!("../../src/runtime/contracts.rs"),
        include_str!("../../src/runtime/channels.rs"),
        include_str!("../../src/runtime/entrypoint.rs"),
    );
    let install = include_str!("../../../../scripts/install-local.sh");
    let protocol = include_str!("../../../niralis-session/src/protocol.rs");
    assert!(cargo.contains("required-features = [\"worker-test-fixtures\"]"));
    assert!(!cargo.contains("default = [\"worker-test-fixtures\"]"));
    assert!(!install.contains("worker-test-fixtures"));
    assert!(!production_main.contains("test-mode"));
    assert!(!production_main.contains("NIRALIS_TEST_PHASE"));
    assert!(!runtime.contains("NIRALIS_TEST_PHASE"));
    assert!(!protocol.contains("WorkerLaunchPhase"));
    assert_eq!(niralis_session::WORKER_PROTOCOL_VERSION, 12);
    assert_eq!(niralis_session::WORKER_CONTROL_PROTOCOL_VERSION, 3);
    assert_eq!(niralis_session_worker::SESSION_CHILD_PROTOCOL_VERSION, 9);
    assert_eq!(niralis_session_worker::SESSION_EXEC_PROBE_VERSION, 2);
}

#[test]
fn probe_abort_and_reap_exactly_once_at_barrier_a() {
    run_barrier_a();
}

#[test]
fn probe_abort_and_reap_exactly_once_at_barrier_b() {
    run_barrier_b();
}

#[test]
fn probe_abort_and_reap_exactly_once_at_barrier_c() {
    run_barrier_c_released(false);
}
