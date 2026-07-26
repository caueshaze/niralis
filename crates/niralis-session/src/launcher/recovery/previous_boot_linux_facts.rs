use super::super::*;
use crate::launcher::recovery::vt_busy_support::proc_starttime;
use std::fs;
use zbus::zvariant::OwnedObjectPath;

type SystemdUnitListEntry = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

pub(super) fn list_current_scopes(
    connection: &zbus::blocking::Connection,
) -> Result<Vec<CurrentScopeFacts>, PreviousBootInspectionError> {
    let manager = zbus::blocking::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .map_err(|_| PreviousBootInspectionError::Unavailable)?;
    let units: Vec<SystemdUnitListEntry> = manager
        .call("ListUnits", &())
        .map_err(|_| PreviousBootInspectionError::Unavailable)?;
    units
        .into_iter()
        .filter(|(id, ..)| id.starts_with("niralis-") && id.ends_with(".scope"))
        .map(|(_, _, _, _, _, _, path, _, _, _)| {
            let value = read_unit_observation(connection, &path)
                .map_err(|_| PreviousBootInspectionError::Unavailable)?;
            Ok(CurrentScopeFacts {
                unit_name: value.id,
                object_path: value.object_path,
                invocation_id: value.invocation_id,
                control_group: value.control_group,
                slice: value.slice,
                transient: value.transient,
                active_state: value.active_state,
                sub_state: value.sub_state,
            })
        })
        .collect()
}

pub(super) fn list_current_sessions(
    seat: &str,
) -> Result<Vec<CurrentSessionFacts>, PreviousBootInspectionError> {
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| PreviousBootInspectionError::Unavailable)?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| PreviousBootInspectionError::Unavailable)?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        LOGIND_DESTINATION,
        LOGIND_MANAGER_PATH,
        LOGIND_MANAGER_INTERFACE,
    )
    .map_err(|_| PreviousBootInspectionError::Unavailable)?;
    let entries: Vec<(String, u32, String, String, OwnedObjectPath)> = manager
        .call("ListSessions", &())
        .map_err(|_| PreviousBootInspectionError::Unavailable)?;
    entries
        .into_iter()
        .filter(|(_, _, _, listed_seat, _)| seat == "*" || listed_seat == seat)
        .map(|(listed_id, _, _, _, path)| {
            let session = zbus::blocking::Proxy::new(
                &connection,
                LOGIND_DESTINATION,
                path.as_str(),
                LOGIND_SESSION_INTERFACE,
            )
            .map_err(|_| PreviousBootInspectionError::Unavailable)?;
            let session_id: String = session
                .get_property("Id")
                .map_err(|_| PreviousBootInspectionError::Unavailable)?;
            Ok(CurrentSessionFacts {
                session_id: if session_id.is_empty() {
                    listed_id
                } else {
                    session_id
                },
                object_path: path.to_string(),
                seat: session
                    .get_property("Seat")
                    .map_err(|_| PreviousBootInspectionError::Unavailable)?,
                leader_pid: session
                    .get_property("Leader")
                    .map_err(|_| PreviousBootInspectionError::Unavailable)?,
                vt: session
                    .get_property("VTNr")
                    .map_err(|_| PreviousBootInspectionError::Unavailable)?,
                state: session
                    .get_property("State")
                    .map_err(|_| PreviousBootInspectionError::Unavailable)?,
                scope: session
                    .get_property("Scope")
                    .map_err(|_| PreviousBootInspectionError::Unavailable)?,
            })
        })
        .collect()
}

pub(super) fn current_conflicts(
    request: &PreviousBootInspectionRequest,
    scopes: &[CurrentScopeFacts],
    sessions: &[CurrentSessionFacts],
) -> CurrentBootConflictFacts {
    let old = &request.record.record;
    CurrentBootConflictFacts {
        same_unit_name: observation(
            scopes
                .iter()
                .any(|s| old.payload_unit.as_deref() == Some(s.unit_name.as_str())),
        ),
        same_invocation_id: observation(
            scopes
                .iter()
                .any(|s| old.invocation_id.as_deref() == Some(s.invocation_id.as_str())),
        ),
        same_cgroup_path: observation(
            scopes
                .iter()
                .any(|s| old.control_group.as_deref() == Some(s.control_group.as_str())),
        ),
        same_session_id: observation(
            sessions
                .iter()
                .any(|s| old.logind_session_id.as_deref() == Some(s.session_id.as_str())),
        ),
        same_lifecycle_id: observation(request.records.iter().any(|r| {
            r.lifecycle_id == old.lifecycle_id && r.created_boot_id != old.created_boot_id
        })),
    }
}

fn observation(present: bool) -> CurrentIdentityObservation {
    if present {
        CurrentIdentityObservation::PresentButDifferentIdentity
    } else {
        CurrentIdentityObservation::Absent
    }
}

pub(super) fn current_seat(
    request: &PreviousBootInspectionRequest,
    scopes: &[CurrentScopeFacts],
    sessions: &[CurrentSessionFacts],
    current_boot: &BootIdentity,
) -> CurrentSeatFacts {
    let current_record = request.records.iter().find(|r| {
        r.seat == request.record.record.seat && r.created_boot_id == current_boot.as_str()
    });
    let runtime_state = if current_record.is_some() {
        CurrentSeatRuntimeState::ClaimedByCurrentLifecycle
    } else if !scopes.is_empty() || !sessions.is_empty() {
        CurrentSeatRuntimeState::Conflicting
    } else {
        CurrentSeatRuntimeState::Unclaimed
    };
    CurrentSeatFacts {
        runtime_state,
        inspection_complete: true,
        active_lifecycle: current_record.map(|r| r.lifecycle_id.clone()),
        sessions: sessions.to_vec(),
        scopes: scopes.to_vec(),
    }
}

pub(super) fn historical_pid_collisions(
    record: &PersistentRecoveryRecord,
) -> Vec<HistoricalIdentityCollision> {
    [
        (
            record.worker_pid,
            record.worker_starttime,
            record.worker_executable,
        ),
        (
            record.launcher_pid,
            record.launcher_starttime,
            record.launcher_executable,
        ),
        (
            record.leader_pid.unwrap_or_default(),
            record.leader_starttime,
            record.leader_executable,
        ),
    ]
    .into_iter()
    .filter(|(pid, _, _)| *pid != 0 && fs::metadata(format!("/proc/{pid}")).is_ok())
    .map(
        |(pid, historical_starttime, historical_executable)| HistoricalIdentityCollision {
            pid,
            historical_starttime,
            current_starttime: proc_starttime(pid),
            historical_executable,
            current_executable: fs::metadata(format!("/proc/{pid}/exe"))
                .ok()
                .map(|m| (m.dev(), m.ino())),
            current_cgroup: fs::read_to_string(format!("/proc/{pid}/cgroup"))
                .ok()
                .and_then(|v| {
                    v.lines()
                        .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
                }),
        },
    )
    .collect()
}
