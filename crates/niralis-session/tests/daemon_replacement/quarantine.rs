#[test]
fn same_boot_empty_boundary_skips_emergency_kill() {
    let mut daemon_a = DaemonFixture::spawn("empty");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("empty", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(daemon_b.events().contains("proof:empty_boundary\n"));
    assert!(!daemon_b.events().contains("payload_kill\n"));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    daemon_b.kill_exact();
}

#[test]
fn replacement_quarantines_without_targeting_new_unit() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("replacement", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_some());
    assert!(!daemon_b.events().contains("payload_kill\n"));
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn real_unknown_scope_without_known_seat_quarantines_globally() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("unknown", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(daemon_b.events().contains("quarantine:unknown_scope\n"));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_some());
    assert!(!daemon_b.events().contains("payload_kill\n"));
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn indeterminate_kill_does_not_repeat() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    kill_pidfd(&worker);
    let record = rewrite_record(&daemon_a.recovery, "started", true);

    let mut daemon_b =
        DaemonFixture::spawn_reusing_storage("payload-recovered", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(daemon_b
        .events()
        .contains("quarantine:indeterminate_payload_kill\n"));
    assert_eq!(
        daemon_b
            .events()
            .lines()
            .filter(|line| line.starts_with("payload_kill "))
            .count(),
        0
    );
    assert!(fs::metadata(record).is_ok());
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn indeterminate_kill_with_empty_boundary_continues() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    rewrite_record(&daemon_a.recovery, "started", true);

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("empty", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert_eq!(
        daemon_b
            .events()
            .lines()
            .filter(|line| line.starts_with("payload_kill "))
            .count(),
        0
    );
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    daemon_b.kill_exact();
}

#[test]
fn vt_ebusy_quarantine_survives_daemon_replacement() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    rewrite_record(&daemon_a.recovery, "vt_disallocate_failed_busy", false);

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("ebusy", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
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

#[test]
fn second_login_starts_after_reconciled_replacement() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let first = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let first_record = record_path(&daemon_a.recovery);
    let first_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&first_record).expect("first record")).unwrap();
    let first_lifecycle = first_json["lifecycle_id"].as_str().unwrap().to_owned();
    let first_worker = pidfd_open(first[0]);
    let first_leader = pidfd_open(first[1]);
    let first_member = pidfd_open(first[2]);
    daemon_a.kill_exact();

    let mut daemon_b =
        DaemonFixture::spawn_reusing_storage("restart-reconciles", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("resolved recovery directory")
        .next()
        .is_none());
    kill_pidfd(&first_worker);
    kill_pidfd(&first_leader);
    kill_pidfd(&first_member);
    daemon_b.kill_exact();

    let mut daemon_c =
        DaemonFixture::spawn_reusing_storage("restart-reconciles", &daemon_a.recovery);
    assert!(daemon_c.receive_barrier().starts_with("ready "));
    daemon_c.start();
    let second = daemon_c.receive_processes();
    assert!(daemon_c.receive_barrier().starts_with("started "));
    let second_record = record_path(&daemon_a.recovery);
    let second_json: serde_json::Value =
        serde_json::from_slice(&fs::read(second_record).expect("second record")).unwrap();
    assert_ne!(
        first_lifecycle,
        second_json["lifecycle_id"].as_str().unwrap()
    );
    let second_worker = pidfd_open(second[0]);
    let second_leader = pidfd_open(second[1]);
    let second_member = pidfd_open(second[2]);
    daemon_c.kill_exact();
    kill_pidfd(&second_worker);
    kill_pidfd(&second_leader);
    kill_pidfd(&second_member);
}

