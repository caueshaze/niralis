fn assert_startup_quarantine_mode(mode: &str, expected_event: &str) {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let mut daemon_b = DaemonFixture::spawn_reusing_storage(mode, &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(
        daemon_b.events().contains(expected_event),
        "events={:?}",
        daemon_b.events()
    );
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("quarantined recovery directory")
        .next()
        .is_some());
    assert_eq!(
        daemon_b
            .events()
            .lines()
            .filter(|line| line.starts_with("payload_kill "))
            .count(),
        0
    );
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

