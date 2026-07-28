#[test]
fn daemon_a_reaches_durable_started_before_replacement() {
    let mut daemon_a = DaemonFixture::spawn("restart-reconciles");
    let ready_a = daemon_a.receive_barrier();
    assert!(ready_a.starts_with("ready "), "{ready_a}");
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    let started = daemon_a.receive_barrier();
    assert!(started.starts_with("started "), "{started}");

    let records = fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .map(|entry| entry.expect("record entry").path())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(&records[0]).expect("durable record bytes"))
            .expect("durable record JSON");
    assert_eq!(record["state"], "started");
    assert!(record["lifecycle_id"].as_str().is_some());
    assert!(record["invocation_id"].as_str().is_some());

    let worker_pid = pidfd_open(processes[0]);
    let leader_pid = pidfd_open(processes[1]);
    let member_pid = pidfd_open(processes[2]);
    assert!(proc_exists(processes[0]));
    assert!(proc_exists(processes[1]));
    assert!(proc_exists(processes[2]));

    let daemon_a_pid = daemon_a.child.id();
    daemon_a.kill_exact();
    assert!(!proc_exists(daemon_a_pid));
    assert!(proc_exists(processes[0]));
    assert!(proc_exists(processes[1]));
    assert!(proc_exists(processes[2]));
    assert!(fs::metadata(&records[0]).is_ok());

    let mut daemon_b =
        DaemonFixture::spawn_reusing_storage("restart-reconciles", &daemon_a.recovery);
    let ready_b = daemon_b.receive_barrier();
    assert!(ready_b.starts_with("ready "), "{ready_b}");
    assert!(daemon_b.child.id() != daemon_a_pid);
    let remaining = fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory after B")
        .map(|entry| {
            let path = entry.expect("remaining record").path();
            (
                path.clone(),
                fs::read_to_string(path).expect("remaining record bytes"),
            )
        })
        .collect::<Vec<_>>();
    assert!(remaining.is_empty(), "remaining records: {remaining:?}");

    kill_pidfd(&worker_pid);
    kill_pidfd(&leader_pid);
    kill_pidfd(&member_pid);
    daemon_b.kill_exact();
}

#[test]
fn same_boot_worker_alive_handoff_completes() {
    let mut daemon_a = DaemonFixture::spawn("worker-alive");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("worker-alive", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    wait_pidfd(&worker);
    assert!(daemon_b.events().contains("worker_sigterm\n"));
    assert!(!daemon_b.events().contains("payload_kill\n"));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn same_boot_worker_alive_handoff_escalates_after_sigterm() {
    let mut daemon_a = DaemonFixture::spawn_with_env(
        "worker-alive",
        &[("NIRALIS_FIXTURE_WORKER_IGNORE_SIGTERM", "1")],
    );
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("worker-alive", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    wait_pidfd(&worker);
    let events = daemon_b.events();
    assert!(events.contains("worker_sigterm\n"));
    assert!(events.contains("worker_sigkill\n"));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn same_boot_worker_alive_handoff_retries_persisted_runtime_release() {
    let mut daemon_a = DaemonFixture::spawn("worker-alive");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    rewrite_runtime_release(
        &daemon_a.recovery,
        serde_json::json!({ "IntentPersisted": { "attempt_id": 41 } }),
        None,
    );

    let mut daemon_b = DaemonFixture::spawn_reusing_storage("worker-alive", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    wait_pidfd(&worker);
    assert!(daemon_b.events().contains("worker_sigterm\n"));
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    kill_pidfd(&leader);
    kill_pidfd(&member);
    daemon_b.kill_exact();
}

#[test]
fn same_boot_worker_gone_payload_is_recovered() {
    let mut daemon_a = DaemonFixture::spawn("payload-recovered");
    assert!(daemon_a.receive_barrier().starts_with("ready "));
    daemon_a.start();
    let processes = daemon_a.receive_processes();
    assert!(daemon_a.receive_barrier().starts_with("started "));
    let worker = pidfd_open(processes[0]);
    let leader = pidfd_open(processes[1]);
    let member = pidfd_open(processes[2]);
    daemon_a.kill_exact();
    kill_pidfd(&worker);
    assert!(proc_exists(processes[1]));
    assert!(proc_exists(processes[2]));

    let mut daemon_b =
        DaemonFixture::spawn_reusing_storage("payload-recovered", &daemon_a.recovery);
    assert!(daemon_b.receive_barrier().starts_with("ready "));
    let events = daemon_b.events();
    let kill = events
        .lines()
        .find(|line| line.starts_with("payload_kill "))
        .unwrap_or_else(|| panic!("invocation-bound payload kill event; events={events:?}"));
    assert!(kill.contains("unit=niralis-payload-"), "event={kill}");
    assert!(kill.contains("invocation="), "event={kill}");
    assert!(
        kill.contains("object_path=/org/freedesktop/systemd1/unit/"),
        "event={kill}"
    );
    assert!(kill.contains("cgroup="), "event={kill}");
    wait_pidfd(&leader);
    assert_eq!(
        daemon_b
            .events()
            .lines()
            .filter(|line| line.starts_with("payload_kill "))
            .count(),
        1
    );
    assert!(fs::read_dir(&daemon_a.recovery)
        .expect("recovery directory")
        .next()
        .is_none());
    kill_pidfd(&member);
    daemon_b.kill_exact();
}
