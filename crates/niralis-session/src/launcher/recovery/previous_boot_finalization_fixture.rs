use super::*;

pub(crate) fn record(id: &str) -> PersistentRecoveryRecord {
    PersistentRecoveryRecord {
        format_version: RECOVERY_FORMAT_VERSION,
        lifecycle_id: id.to_owned(),
        sequence: 1,
        created_at_unix: 1,
        created_boot_id: "boot-old".to_owned(),
        last_updated_boot_id: "boot-old".to_owned(),
        state: "started".to_owned(),
        uid: 1000,
        gid: 1000,
        username: "user".to_owned(),
        session_name: "niri".to_owned(),
        seat: "seat0".to_owned(),
        worker_pid: 1,
        launcher_pid: 1,
        launcher_starttime: None,
        launcher_executable: None,
        worker_starttime: None,
        worker_executable: None,
        worker_cgroup: None,
        leader_pid: None,
        leader_starttime: None,
        leader_executable: None,
        payload_unit: None,
        transient: None,
        invocation_id: None,
        object_path: None,
        control_group: None,
        slice: None,
        logind_session_id: None,
        logind_object_path: None,
        target_vt: Some(3),
        previous_vt: Some(1),
        pam_status: "closed".to_owned(),
        operation_ledger: DurableOperationLedger::default(),
        quarantine_reason: None,
        vt_busy_provenance: None,
        vt_recovery_attempts: Vec::new(),
    }
}

pub(crate) fn facts() -> PreviousBootCurrentFacts {
    PreviousBootCurrentFacts {
        authority: CurrentAuthorityFacts {
            systemd_owner: Some("controlled-systemd".to_owned()),
            systemd_generation: Some(0),
            logind_owner: Some("controlled-logind".to_owned()),
            logind_generation: Some(0),
            stable: true,
        },
        seat: CurrentSeatFacts {
            runtime_state: CurrentSeatRuntimeState::Unclaimed,
            inspection_complete: true,
            active_lifecycle: None,
            sessions: Vec::new(),
            scopes: Vec::new(),
        },
        vt: Some(CurrentVtFacts {
            target_vt: 3,
            active_vt: Some(1),
            disposition: CurrentVtDisposition::NotForegroundAndUnused,
            inspection_complete: true,
            visible_holders: Vec::new(),
        }),
        ..PreviousBootCurrentFacts::default()
    }
}

pub(crate) fn host() -> ControlledPreviousBootInspectionHost {
    let mut host = ControlledPreviousBootInspectionHost {
        boot: Some(BootIdentity::parse("boot-current").unwrap()),
        authority_stable: true,
        ..ControlledPreviousBootInspectionHost::default()
    };
    host.seats.insert("seat0".to_owned(), facts().seat);
    host.vts.insert(3, facts().vt.unwrap());
    host
}

pub(crate) fn previous(record: PersistentRecoveryRecord) -> PreviousBootRecoveryRecord {
    match RecoveryRecordEpoch::classify(record, BootIdentity::parse("boot-current").unwrap())
        .unwrap()
    {
        RecoveryRecordEpoch::PreviousBoot(value) => value,
        RecoveryRecordEpoch::SameBoot(_) => panic!("expected previous boot"),
    }
}
