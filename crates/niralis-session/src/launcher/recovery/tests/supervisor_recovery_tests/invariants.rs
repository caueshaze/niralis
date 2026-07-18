use super::*;

#[test]
fn supervisor_pidfd_observes_old_process_without_waitpid() {
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "exec sleep 30"])
        .spawn()
        .unwrap();
    let pidfd = SupervisorLeaderPidfd::open(child.id()).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(pidfd.observed_dead().unwrap());
}

#[test]
fn emergency_supervisor_never_reconstructs_or_closes_pam() {
    let source = recovery_source();
    assert!(!source.contains("pam_start"));
    assert!(!source.contains("pam_close_session"));
    assert!(!source.contains("waitpid("));
    assert!(!source.contains("Manager.KillUnit"));
    assert!(!source.contains("kill(-(pgid"));
}

#[test]
fn emergency_proof_is_not_worker_boundary_empty_proof() {
    let source = recovery_source();
    assert!(source.contains("struct SupervisorEmergencyBoundaryProof"));
    assert!(!source.contains("SupervisorEmergencyBoundaryProof -> BoundaryEmptyProof"));
}

#[test]
fn payload_scope_identity_does_not_require_logind_cgroup_membership() {
    let logind_identity = include_str!("../../logind_identity.rs");
    let systemd_pin = include_str!("../../systemd_pin.rs");
    assert!(!logind_identity.contains("sd_pid_get_session"));
    assert!(systemd_pin.contains("leader_cgroup != second.control_group"));
}

#[test]
fn emergency_vt_releases_the_target_before_using_a_separate_control_tty() {
    let vt = include_str!("../../vt.rs");
    let target_release = vt.find("drop(tty_fd);").unwrap();
    let control_open = vt.find("CString::new(\"/dev/tty0\")").unwrap();
    let disallocate = vt.find("VT_DISALLOCATE").unwrap();
    assert!(target_release < control_open && control_open < disallocate);
    assert!(!vt.contains("try_clone"));
    assert!(!vt.contains("dup("));
}

fn recovery_source() -> String {
    [
        include_str!("../../boundary.rs"),
        include_str!("../../boundary_proof.rs"),
        include_str!("../../coordinator.rs"),
        include_str!("../../linux_provider.rs"),
        include_str!("../../logind_cleanup.rs"),
        include_str!("../../model.rs"),
        include_str!("../../systemd_pin.rs"),
        include_str!("../../vt.rs"),
    ]
    .join("\n")
}
