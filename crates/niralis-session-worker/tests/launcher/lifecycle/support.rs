use std::path::PathBuf;
use std::time::Duration;

use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{
    SessionError, SessionExecPlan, SessionRequest, StartedSession, WorkerSecret,
    WorkerSessionLauncher,
};

fn request() -> SessionRequest {
    SessionRequest {
        username: "test".to_owned(),
        session: SessionInfo {
            id: "niri".to_owned(),
            name: "Niri".to_owned(),
            kind: SessionKind::Wayland,
        },
    }
}

fn plan() -> SessionExecPlan {
    SessionExecPlan {
        source_path: b"/source.desktop".to_vec(),
        executable: b"/bin/true".to_vec(),
        argv: vec![b"true".to_vec()],
    }
}

fn launcher_for(bin: &str) -> WorkerSessionLauncher {
    WorkerSessionLauncher::new(
        PathBuf::from(bin),
        PathBuf::from("/usr/libexec/niralis-session-child"),
        PathBuf::from("/usr/libexec/niralis-session-probe"),
        Duration::from_millis(200),
        Vec::new(),
    )
    .expect("launcher should build")
}

fn controlled_launcher(bin: &str) -> WorkerSessionLauncher {
    let mut launcher = WorkerSessionLauncher::new(
        PathBuf::from(bin),
        PathBuf::from("/usr/libexec/niralis-session-child"),
        PathBuf::from("/usr/libexec/niralis-session-probe"),
        Duration::from_secs(2),
        Vec::new(),
    )
    .expect("controlled launcher should build");
    launcher.use_supervisor_test_fixture_for_test();
    launcher.use_inherited_supervisor_control_for_test();
    launcher
}

fn controlled_launcher_real_socketpair(bin: &str) -> WorkerSessionLauncher {
    let mut launcher = WorkerSessionLauncher::new(
        PathBuf::from(bin),
        PathBuf::from("/usr/libexec/niralis-session-child"),
        PathBuf::from("/usr/libexec/niralis-session-probe"),
        Duration::from_secs(2),
        Vec::new(),
    )
    .expect("controlled launcher should build");
    launcher.use_supervisor_test_fixture_for_test();
    launcher.use_inherited_supervisor_control_for_test();
    launcher
}

#[test]
fn worker_launcher_returns_started_session() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_niralis-session-worker"));
    let started = launcher
        .start_prepared_session_for_test(request())
        .expect("worker launcher should succeed");
    assert_eq!(
        started,
        StartedSession {
            username: "test".to_owned(),
            session: SessionInfo {
                id: "niri".to_owned(),
                name: "Niri".to_owned(),
                kind: SessionKind::Wayland,
            },
        }
    );
}

#[test]
fn started_without_registered_payload_scope_is_rejected() {
    let launcher = launcher_for(env!("CARGO_BIN_EXE_fixture-started-then-hang"));
    assert_eq!(
        launcher.start_prepared_session_for_test(request()),
        Err(SessionError::WorkerProtocolFailed)
    );
}
