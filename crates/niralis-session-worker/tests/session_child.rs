use std::path::PathBuf;

use niralis_session_worker::{
    PrivilegeDropTarget, ProcessSessionChildRunner, SessionChildError, SessionChildExpectation,
    SessionChildRunner, SessionChildRuntimeContext, SessionChildUnixPath,
};

fn runner(binary: &str) -> ProcessSessionChildRunner {
    ProcessSessionChildRunner::new(PathBuf::from(binary)).expect("fixture path should be absolute")
}

#[test]
fn ready_does_not_commit_exec_automatically() {
    let runner = runner(env!("CARGO_BIN_EXE_fixture-child-ready-hang"));
    let pending = runner
        .run_child_until_ready(expectation())
        .expect("post-exec Ready should produce a pending handoff");
    let pid = pending.report().child_pid;
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, 0);
    std::thread::sleep(std::time::Duration::from_millis(30));
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, 0);
    pending
        .abort()
        .expect("abort should reap the blocked probe");
}

#[test]
fn explicit_commit_transfers_the_same_authoritative_pid() {
    let runner = runner(env!("CARGO_BIN_EXE_fixture-child-ready-hang"));
    let pending = runner
        .run_child_until_ready(expectation())
        .expect("post-exec Ready should produce a pending handoff");
    let pid = pending.report().child_pid;
    let report = pending.commit_exec().expect("CommitExec should succeed");
    assert_eq!(report.child_pid, pid);
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) }, 0);
    let status = runner
        .wait_for_child()
        .expect("committed child should be owned by runner");
    assert!(!status.success());
}

#[test]
fn dropping_pending_handoff_aborts_and_reaps_the_probe() {
    let runner = runner(env!("CARGO_BIN_EXE_fixture-child-ready-hang"));
    let pending = runner
        .run_child_until_ready(expectation())
        .expect("post-exec Ready should produce a pending handoff");
    let pid = pending.report().child_pid;
    drop(pending);
    std::thread::sleep(std::time::Duration::from_millis(30));
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
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
            selinux_exec_context: None,
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
    let report = runner
        .run_child(expectation())
        .expect("exec acceptance should complete before natural exit");
    assert_eq!(
        unsafe { libc::kill(report.child_pid as libc::pid_t, libc::SIGUSR1) },
        0
    );
    let status = runner
        .wait_for_child()
        .expect("natural exit should be reaped");
    assert!(!status.success());
}
