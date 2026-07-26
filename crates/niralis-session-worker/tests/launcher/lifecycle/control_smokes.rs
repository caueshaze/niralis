#[test]
fn test_control_smoke_graceful_terminates_owned_runtime() {
    let launcher = controlled_launcher(env!("CARGO_BIN_EXE_fixture-control-graceful"));
    let (started, runtime_id) = launcher
        .start_pam_session_for_test(
            request(),
            plan(),
            "test".to_owned(),
            WorkerSecret::new("test".to_owned()),
        )
        .expect("controlled fixture should start");
    assert_eq!(started.username, "test");
    assert_eq!(started.session, request().session);
    launcher
        .terminate_runtime_session_for_test(runtime_id)
        .expect("graceful termination should be accepted");
}

#[test]
fn test_control_smoke_stubborn_escalates_after_grace_period() {
    let launcher = controlled_launcher(env!("CARGO_BIN_EXE_fixture-control-stubborn"));
    let (_, runtime_id) = launcher
        .start_pam_session_for_test(
            request(),
            plan(),
            "test".to_owned(),
            WorkerSecret::new("test".to_owned()),
        )
        .expect("stubborn fixture should start");
    launcher
        .terminate_runtime_session_for_test(runtime_id)
        .expect("stubborn termination should be accepted");
}

#[test]
#[ignore = "requires a real AF_UNIX host path; run explicitly on Hiraeth"]
fn test_control_smoke_stubborn_real_socketpair_20x() {
    assert!(
        matches!(
            niralis_session_worker::probe_af_unix_environment_support(),
            niralis_session_worker::AfUnixEnvironmentProbe::Supported
        ),
        "real AF_UNIX host support is required"
    );
    for iteration in 1..=20 {
        eprintln!("host stubborn smoke iteration={iteration}/20");
        let launcher =
            controlled_launcher_real_socketpair(env!("CARGO_BIN_EXE_fixture-control-stubborn"));
        let (started, runtime_id) = launcher
            .start_pam_session_for_test(
                request(),
                plan(),
                "test".to_owned(),
                WorkerSecret::new("test".to_owned()),
            )
            .expect("stubborn fixture should start on inherited socketpair");
        assert_eq!(started.username, "test");
        assert_eq!(started.session, request().session);
        launcher
            .terminate_runtime_session_for_test(runtime_id)
            .expect("stubborn termination should be accepted on inherited socketpair");
    }
}
