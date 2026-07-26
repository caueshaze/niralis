use super::*;

use super::previous_boot_linux_facts::*;
use super::previous_boot_linux_vt::inspect_vt;

#[derive(Debug, Default)]
pub(crate) struct LinuxPreviousBootInspectionHost;

impl PreviousBootInspectionHost for LinuxPreviousBootInspectionHost {
    fn current_boot_identity(&self) -> Result<BootIdentity, PreviousBootInspectionError> {
        BootIdentity::parse(
            current_boot_id().map_err(|_| PreviousBootInspectionError::Unavailable)?,
        )
    }

    fn inspect_current_conflicts(
        &self,
        request: &PreviousBootConflictRequest,
    ) -> Result<CurrentBootConflictFacts, PreviousBootInspectionError> {
        let connection = zbus::blocking::connection::Builder::system()
            .map_err(|_| PreviousBootInspectionError::Unavailable)?
            .method_timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| PreviousBootInspectionError::Unavailable)?;
        let scopes = list_current_scopes(&connection)?;
        let sessions = list_current_sessions("*")?;
        Ok(CurrentBootConflictFacts {
            same_unit_name: observe(
                scopes
                    .iter()
                    .any(|scope| request.payload_unit.as_deref() == Some(scope.unit_name.as_str())),
            ),
            same_invocation_id: observe(scopes.iter().any(|scope| {
                request.invocation_id.as_deref() == Some(scope.invocation_id.as_str())
            })),
            same_cgroup_path: observe(scopes.iter().any(|scope| {
                request.control_group.as_deref() == Some(scope.control_group.as_str())
            })),
            same_session_id: observe(sessions.iter().any(|session| {
                request.logind_session_id.as_deref() == Some(session.session_id.as_str())
            })),
            same_lifecycle_id: CurrentIdentityObservation::Absent,
        })
    }

    fn inspect_current_seat(
        &self,
        seat: &str,
    ) -> Result<CurrentSeatFacts, PreviousBootInspectionError> {
        let scopes = {
            let connection = zbus::blocking::connection::Builder::system()
                .map_err(|_| PreviousBootInspectionError::Unavailable)?
                .method_timeout(Duration::from_secs(2))
                .build()
                .map_err(|_| PreviousBootInspectionError::Unavailable)?;
            list_current_scopes(&connection)?
        };
        let sessions = list_current_sessions(seat)?;
        Ok(CurrentSeatFacts {
            runtime_state: if scopes.is_empty() && sessions.is_empty() {
                CurrentSeatRuntimeState::Unclaimed
            } else {
                CurrentSeatRuntimeState::Conflicting
            },
            inspection_complete: true,
            active_lifecycle: None,
            sessions,
            scopes,
        })
    }

    fn inspect_current_vt(&self, vt: u32) -> Result<CurrentVtFacts, PreviousBootInspectionError> {
        inspect_vt(vt)
    }

    fn inspect_current_snapshot(
        &self,
        request: &PreviousBootInspectionRequest,
    ) -> Result<PreviousBootCurrentFacts, PreviousBootInspectionError> {
        let boot = self.current_boot_identity()?;
        let systemd = zbus::blocking::connection::Builder::system()
            .map_err(|_| PreviousBootInspectionError::Unavailable)?
            .method_timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| PreviousBootInspectionError::Unavailable)?;
        let systemd_owner_before =
            systemd_owner(&systemd).map_err(|_| PreviousBootInspectionError::Unavailable)?;
        let scopes = list_current_scopes(&systemd)?;
        let logind_owner_before =
            logind_owner().map_err(|_| PreviousBootInspectionError::Unavailable)?;
        let sessions = list_current_sessions(&request.record.record.seat)?;
        let conflicts = current_conflicts(request, &scopes, &sessions);
        let seat = current_seat(request, &scopes, &sessions, &boot);
        let vt = request
            .record
            .record
            .target_vt
            .map(inspect_vt)
            .transpose()?;
        let historical_pid_reuse = historical_pid_collisions(&request.record.record);
        let systemd_owner_after =
            systemd_owner(&systemd).map_err(|_| PreviousBootInspectionError::Unavailable)?;
        let logind_owner_after =
            logind_owner().map_err(|_| PreviousBootInspectionError::Unavailable)?;
        if systemd_owner_before != systemd_owner_after || logind_owner_before != logind_owner_after
        {
            return Err(PreviousBootInspectionError::AuthorityChanged);
        }
        Ok(PreviousBootCurrentFacts {
            authority: CurrentAuthorityFacts {
                systemd_owner: Some(systemd_owner_before),
                systemd_generation: Some(0),
                logind_owner: Some(logind_owner_before),
                logind_generation: Some(0),
                stable: true,
            },
            conflicts,
            seat,
            scopes: scopes.clone(),
            sessions,
            historical_pid_reuse,
            vt,
            competing_records: request
                .records
                .iter()
                .filter(|record| {
                    record.seat == request.record.record.seat
                        && record.lifecycle_id != request.record.record.lifecycle_id
                })
                .map(|record| record.lifecycle_id.clone())
                .collect(),
            inspection_failures: Vec::new(),
            has_newer_record_for_seat: request.records.iter().any(|record| {
                record.seat == request.record.record.seat
                    && record.sequence > request.record.record.sequence
            }),
            has_same_boot_record_for_seat: request.records.iter().any(|record| {
                record.seat == request.record.record.seat && record.created_boot_id == boot.as_str()
            }),
            ambiguous_neighbor: false,
        })
    }
}

fn observe(present: bool) -> CurrentIdentityObservation {
    if present {
        CurrentIdentityObservation::PresentButDifferentIdentity
    } else {
        CurrentIdentityObservation::Absent
    }
}
