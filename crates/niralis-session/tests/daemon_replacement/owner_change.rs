#[test]
fn systemd_owner_change_before_kill_quarantines() {
    assert_startup_quarantine_mode("systemd-before-kill", "owner_change:invalidated\n");
}

#[test]
fn systemd_owner_change_during_kill_is_indeterminate() {
    assert_startup_quarantine_mode("systemd-during-kill", "owner_change:invalidated\n");
}

#[test]
fn systemd_owner_change_before_proof_blocks_proof() {
    assert_startup_quarantine_mode("systemd-before-proof", "owner_change:invalidated\n");
}

#[test]
fn logind_owner_change_before_terminate_quarantines() {
    assert_startup_quarantine_mode("logind-before-terminate", "owner_change:invalidated\n");
}

#[test]
fn logind_owner_change_during_terminate_is_indeterminate() {
    assert_startup_quarantine_mode("logind-during-cleanup", "owner_change:invalidated\n");
}

#[test]
fn logind_owner_change_before_absence_confirmation_blocks_cleanup() {
    assert_startup_quarantine_mode("logind-before-absence", "owner_change:invalidated\n");
}

#[test]
fn real_systemd_owner_change_invalidates_startup_authority() {
    assert_real_owner_change(
        "real-systemd-owner",
        "org.niralis.fixture.systemd",
        "owner_change:real_name_owner_changed\n",
    );
}

#[test]
fn real_logind_owner_change_invalidates_startup_authority() {
    assert_real_owner_change(
        "real-logind-owner",
        "org.niralis.fixture.logind",
        "owner_change:real_name_owner_changed\n",
    );
}

