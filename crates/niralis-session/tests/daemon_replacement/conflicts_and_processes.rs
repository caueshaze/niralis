#[test]
fn real_unknown_scope_with_known_seat_quarantines_only_that_seat() {
    assert_startup_quarantine_mode("unknown-known-seat", "quarantine:unknown_scope\n");
}

#[test]
fn unknown_scope_record_conflict_is_non_destructive() {
    assert_startup_quarantine_mode("conflict", "quarantine:scope_record_conflict\n");
}

#[test]
fn duplicate_owner_events_keep_operations_single_shot() {
    // Re-running the same replacement against preserved authority loss must
    // never turn quarantine into a second destructive attempt.
    for _ in 0..2 {
        assert_startup_quarantine_mode("systemd-during-kill", "owner_change:invalidated\n");
    }
}

fn proc_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn proc_starttime(pid: u32) -> Option<u64> {
    let value = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    value
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn pidfd_open(pid: u32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    assert!(fd >= 0, "pidfd_open failed for {pid}");
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

fn kill_pidfd(pidfd: &OwnedFd) {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            0,
            0,
        )
    };
    assert_eq!(result, 0);
    wait_pidfd(pidfd);
}

fn wait_pidfd(pidfd: &OwnedFd) {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut pollfd, 1, 5_000) };
    assert_eq!(result, 1);
    assert_ne!(pollfd.revents & libc::POLLIN, 0);
}
