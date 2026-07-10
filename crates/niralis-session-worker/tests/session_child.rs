use std::path::PathBuf;

use niralis_session_worker::{
    PrivilegeDropTarget, ProcessSessionChildRunner, SessionChildError, SessionChildExpectation,
    SessionChildRunner, SessionChildRuntimeContext, SessionChildUnixPath,
};

fn runner(binary: &str) -> ProcessSessionChildRunner {
    ProcessSessionChildRunner::new(PathBuf::from(binary)).expect("fixture path should be absolute")
}

fn expectation() -> SessionChildExpectation {
    SessionChildExpectation {
        canonical_username: "canonical-user".to_owned(),
        session_id: "niri".to_owned(),
        target_credentials: PrivilegeDropTarget {
            uid: 1000,
            gid: 1000,
            supplementary_gids: vec![10, 20],
        },
        runtime: SessionChildRuntimeContext {
            home: SessionChildUnixPath {
                bytes: b"/home/test".to_vec(),
            },
            shell: SessionChildUnixPath {
                bytes: b"/bin/bash".to_vec(),
            },
            session_type: "wayland".into(),
            session_class: String::new(),
            session_desktop: String::new(),
            session_id: String::new(),
            runtime_dir: SessionChildUnixPath { bytes: Vec::new() },
            seat: String::new(),
            vtnr: 0,
            dbus_session_bus_address: None,
            imported_locale: Vec::new(),
            probe_path: SessionChildUnixPath {
                bytes: b"/probe".to_vec(),
            },
            exec_plan: niralis_session::SessionExecPlan {
                source_path: b"/source.desktop".to_vec(),
                executable: b"/bin/true".to_vec(),
                argv: vec![b"true".to_vec()],
            },
        },
        terminal: None,
    }
}

#[test]
fn child_without_response_times_out_and_is_reaped() {
    let error = runner(env!("CARGO_BIN_EXE_fixture-child-no-response"))
        .run_child(expectation())
        .expect_err("silent child should time out");
    assert_eq!(error, SessionChildError::TimedOut);
}

#[test]
fn child_that_never_reads_still_times_out() {
    let error = runner(env!("CARGO_BIN_EXE_fixture-child-no-read"))
        .run_child(expectation())
        .expect_err("non-reading child should time out");
    assert_eq!(error, SessionChildError::TimedOut);
}

#[test]
fn ready_child_remains_alive_after_startup_proof() {
    let runner = runner(env!("CARGO_BIN_EXE_fixture-child-ready-hang"));
    runner
        .run_child(expectation())
        .expect("startup proof should succeed");
    let status = runner
        .wait_for_child()
        .expect("session child should eventually exit");
    assert!(status.success());
}

#[test]
fn nonzero_child_exit_is_reported_after_handshake() {
    let runner = runner(env!("CARGO_BIN_EXE_fixture-child-exit1"));
    runner
        .run_child(expectation())
        .expect("exec acceptance should complete before natural exit");
    let status = runner
        .wait_for_child()
        .expect("natural exit should be reaped");
    assert!(!status.success());
}
