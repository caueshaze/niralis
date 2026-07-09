use std::path::PathBuf;

use niralis_session_worker::{
    ProcessSessionChildRunner, SessionChildExpectation, SessionChildRunner,
};

#[test]
fn real_session_child_completes_handshake_and_exits() {
    let runner =
        ProcessSessionChildRunner::new(PathBuf::from(env!("CARGO_BIN_EXE_niralis-session-child")))
            .expect("child path should be absolute");

    let report = runner
        .run_child(SessionChildExpectation {
            canonical_username: "canonical-user".to_owned(),
            session_id: "niri".to_owned(),
        })
        .expect("child handshake should succeed");

    assert_eq!(report.canonical_username, "canonical-user");
    assert_eq!(report.session_id, "niri");
    assert!(report.child_pid > 0);
}
