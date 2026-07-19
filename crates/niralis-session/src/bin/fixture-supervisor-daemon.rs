use niralis_protocol::{SessionInfo, SessionKind};
use niralis_session::{
    SessionExecPlan, SessionRequest, SupervisorFixtureBoundaryMode, WorkerSecret,
    WorkerSessionLauncher,
};
use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(worker) = args.get(1).map(PathBuf::from) else {
        std::process::exit(2);
    };
    let Some(recovery) = args.get(2).map(PathBuf::from) else {
        std::process::exit(2);
    };
    let Some(lock) = args.get(3).map(PathBuf::from) else {
        std::process::exit(2);
    };
    let Some(report_socket) = args.get(5) else {
        std::process::exit(2);
    };
    let Some(started_barrier) = args.get(6).map(PathBuf::from) else {
        std::process::exit(2);
    };
    let mode = match args.get(4).map(String::as_str) {
        Some("empty") => SupervisorFixtureBoundaryMode::EmptyBoundary,
        Some("restart-reconciles") => SupervisorFixtureBoundaryMode::RestartReconciles,
        Some("worker-alive") => SupervisorFixtureBoundaryMode::WorkerAliveHandoff,
        Some("payload-recovered") => SupervisorFixtureBoundaryMode::PayloadRecovered,
        Some("ebusy") => SupervisorFixtureBoundaryMode::EbusyQuarantine,
        Some("unknown") => SupervisorFixtureBoundaryMode::UnknownScope,
        Some("unknown-known-seat") => SupervisorFixtureBoundaryMode::UnknownScopeKnownSeat,
        Some("conflict") => SupervisorFixtureBoundaryMode::ScopeRecordConflict,
        Some("systemd-before-kill") => SupervisorFixtureBoundaryMode::SystemdOwnerBeforeKill,
        Some("systemd-during-kill") => SupervisorFixtureBoundaryMode::SystemdOwnerDuringKill,
        Some("systemd-before-proof") => SupervisorFixtureBoundaryMode::SystemdOwnerBeforeProof,
        Some("logind-before-terminate") => {
            SupervisorFixtureBoundaryMode::LogindOwnerBeforeTerminate
        }
        Some("logind-during-cleanup") => SupervisorFixtureBoundaryMode::LogindOwnerDuringCleanup,
        Some("logind-before-absence") => SupervisorFixtureBoundaryMode::LogindOwnerBeforeAbsence,
        Some("real-systemd-owner") => SupervisorFixtureBoundaryMode::RealSystemdOwnerChange,
        Some("real-logind-owner") => SupervisorFixtureBoundaryMode::RealLogindOwnerChange,
        Some("real-dbus-payload") => SupervisorFixtureBoundaryMode::RealDbusPayloadRecovery,
        Some("real-dbus-logind") => SupervisorFixtureBoundaryMode::RealDbusLogindCleanup,
        Some("real-dbus-logind-owner") => SupervisorFixtureBoundaryMode::RealDbusLogindOwnerChange,
        _ => SupervisorFixtureBoundaryMode::PopulatedThenRecovered,
    };
    let launcher = WorkerSessionLauncher::new_persistent_supervisor_fixture_for_test(
        worker,
        PathBuf::from("/fixture/session-child"),
        PathBuf::from("/fixture/session-probe"),
        Duration::from_secs(5),
        vec![(
            "NIRALIS_SUPERVISOR_FIXTURE_SOCKET".to_owned(),
            report_socket.clone(),
        )],
        recovery.clone(),
        lock,
        mode,
    )
    .unwrap_or_else(|_| std::process::exit(3));
    send_barrier(
        &started_barrier,
        &format!(
            "ready daemon_pid={} recovery_dir={}",
            std::process::id(),
            recovery.display()
        ),
    );
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else {
            break;
        };
        if line.trim() != "start" {
            continue;
        }
        let result = launcher.start_pam_session_for_test(
            session_request(),
            launch_plan(),
            "fixture".to_owned(),
            WorkerSecret::new("fixture".to_owned()),
        );
        if let Ok((_, runtime_id)) = &result {
            send_barrier(
                &started_barrier,
                &format!(
                    "started daemon_pid={} runtime_id={:?} recovery_dir={}",
                    std::process::id(),
                    runtime_id,
                    recovery.display()
                ),
            );
        }
        println!(
            "{}",
            if result.is_ok() {
                "started"
            } else {
                "rejected"
            }
        );
        if let Err(error) = result {
            eprintln!("fixture daemon start error: {error:?}");
        }
        let _ = io::stdout().flush();
    }
}

fn send_barrier(path: &PathBuf, message: &str) {
    let mut barrier = UnixStream::connect(path).unwrap_or_else(|_| std::process::exit(4));
    writeln!(barrier, "{message}").unwrap_or_else(|_| std::process::exit(4));
    barrier.flush().unwrap_or_else(|_| std::process::exit(4));
}

fn session_request() -> SessionRequest {
    SessionRequest {
        username: "fixture-user".to_owned(),
        session: SessionInfo {
            id: "niri".to_owned(),
            name: "Niri".to_owned(),
            kind: SessionKind::Wayland,
        },
    }
}
fn launch_plan() -> SessionExecPlan {
    SessionExecPlan {
        source_path: b"/fixture/niri.desktop".to_vec(),
        executable: b"/bin/true".to_vec(),
        argv: vec![b"true".to_vec()],
    }
}
