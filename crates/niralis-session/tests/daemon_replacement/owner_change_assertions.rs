fn assert_real_owner_change(mode: &str, replaced_name: &str, expected_event: &str) {
    let mut bus = PrivateBusFixture::start();
    let owner_pid = bus.start_owner(replaced_name);
    let other_name = if replaced_name == "org.niralis.fixture.systemd" {
        "org.niralis.fixture.logind"
    } else {
        "org.niralis.fixture.systemd"
    };
    let _other_pid = bus.start_owner(other_name);

    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let address = bus.address.clone();
    let owner_pid = owner_pid.to_string();
    let environment = [
        ("DBUS_SYSTEM_BUS_ADDRESS", address.as_str()),
        ("NIRALIS_FIXTURE_DBUS_ADDRESS", address.as_str()),
        ("NIRALIS_FIXTURE_DBUS_OWNER_PID", owner_pid.as_str()),
        (
            "NIRALIS_FIXTURE_SYSTEMD_DESTINATION",
            "org.niralis.fixture.systemd",
        ),
        (
            "NIRALIS_FIXTURE_LOGIND_DESTINATION",
            "org.niralis.fixture.logind",
        ),
    ];
    let mut daemon_b =
        DaemonFixture::spawn_reusing_storage_with_env(mode, &daemon_a.recovery, &environment);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    assert!(daemon_b.events().contains(expected_event));
    assert!(!daemon_b.events().contains("payload_kill "));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("preserved recovery directory")
        .next()
        .is_some());

    kill_pidfd(&worker);
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

