#[test]
fn real_dbus_unit_kill_is_invocation_bound_and_single_shot() {
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

    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(record_path(&daemon_a.recovery)).expect("record bytes"))
            .expect("record json");
    let mut bus = PrivateBusFixture::start();
    bus.start_systemd_payload(&record, processes[2], &daemon_a.operation_log);
    let address = bus.address.clone();
    let environment = [
        ("DBUS_SYSTEM_BUS_ADDRESS", address.as_str()),
        ("NIRALIS_FIXTURE_DBUS_ADDRESS", address.as_str()),
    ];
    let mut daemon_b = DaemonFixture::spawn_reusing_storage_with_env(
        "real-dbus-payload",
        &daemon_a.recovery,
        &environment,
    );
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    let events = daemon_b.events();
    assert!(events.contains("proof:startup_dbus"), "events={events:?}");
    assert_eq!(
        events
            .lines()
            .filter(|line| line.starts_with("dbus_unit_kill "))
            .count(),
        1,
        "events={events:?}"
    );
    assert_eq!(
        events
            .lines()
            .filter(|line| line.starts_with("dbus_unit_ref "))
            .count(),
        1,
        "events={events:?}"
    );
    assert_eq!(
        events
            .lines()
            .filter(|line| line.starts_with("dbus_unit_unref "))
            .count(),
        1,
        "events={events:?}"
    );
    assert!(!fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .any(|entry| entry
            .expect("record entry")
            .path()
            .extension()
            .and_then(|v| v.to_str())
            == Some("json")));
    wait_pidfd(&leader);
    wait_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn real_dbus_logind_terminate_is_identity_bound_and_confirmed() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(record_path(&daemon_a.recovery)).expect("record bytes"))
            .expect("record json");
    let mut bus = PrivateBusFixture::start();
    let _systemd_owner = bus.start_owner("org.freedesktop.systemd1");
    bus.start_logind_session(&record, &daemon_a.operation_log);
    let address = bus.address.clone();
    let environment = [
        ("DBUS_SYSTEM_BUS_ADDRESS", address.as_str()),
        ("NIRALIS_FIXTURE_DBUS_ADDRESS", address.as_str()),
    ];
    let mut daemon_b = DaemonFixture::spawn_reusing_storage_with_env(
        "real-dbus-logind",
        &daemon_a.recovery,
        &environment,
    );
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    let events = daemon_b.events();
    assert!(
        events.contains("logind_dbus_terminate_confirmed"),
        "events={events:?}"
    );
    assert_eq!(
        events
            .lines()
            .filter(|line| line.starts_with("dbus_logind_terminate "))
            .count(),
        1,
        "events={events:?}"
    );
    assert!(!fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .any(|entry| entry
            .expect("record entry")
            .path()
            .extension()
            .and_then(|v| v.to_str())
            == Some("json")));
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn real_dbus_logind_owner_change_blocks_terminate() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(record_path(&daemon_a.recovery)).expect("record bytes"))
            .expect("record json");
    let mut bus = PrivateBusFixture::start();
    let _systemd_owner = bus.start_owner("org.freedesktop.systemd1");
    let logind_pid = bus.start_logind_session(&record, &daemon_a.operation_log);
    let address = bus.address.clone();
    let owner_pid = logind_pid.to_string();
    let environment = [
        ("DBUS_SYSTEM_BUS_ADDRESS", address.as_str()),
        ("NIRALIS_FIXTURE_DBUS_ADDRESS", address.as_str()),
        ("NIRALIS_FIXTURE_DBUS_OWNER_PID", owner_pid.as_str()),
    ];
    let mut daemon_b = DaemonFixture::spawn_reusing_storage_with_env(
        "real-dbus-logind-owner",
        &daemon_a.recovery,
        &environment,
    );
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    let events = daemon_b.events();
    assert!(
        events.contains("owner_change:real_logind_before_terminate"),
        "events={events:?}"
    );
    assert!(
        !events.contains("dbus_logind_terminate "),
        "events={events:?}"
    );
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .any(|entry| entry
            .expect("record entry")
            .path()
            .extension()
            .and_then(|v| v.to_str())
            == Some("json")));
    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

