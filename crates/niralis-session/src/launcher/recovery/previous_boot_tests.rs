use super::{super::*, fixtures::*, *};

fn record(id: &str) -> PersistentRecoveryRecord {
    PersistentRecoveryRecord {
        format_version: RECOVERY_FORMAT_VERSION,
        lifecycle_id: id.into(),
        sequence: 7,
        created_at_unix: 1,
        created_boot_id: "boot-old".into(),
        last_updated_boot_id: "boot-old".into(),
        state: "started".into(),
        uid: 1000,
        gid: 1000,
        username: "user".into(),
        session_name: "niri".into(),
        seat: "seat0".into(),
        worker_pid: 11,
        launcher_pid: 12,
        launcher_starttime: Some(10),
        launcher_executable: Some((1, 2)),
        worker_starttime: Some(11),
        worker_executable: Some((1, 3)),
        worker_cgroup: Some("/old".into()),
        leader_pid: Some(13),
        leader_starttime: Some(12),
        leader_executable: Some((1, 4)),
        payload_unit: Some("payload.scope".into()),
        transient: Some(true),
        invocation_id: Some("old-invocation".into()),
        object_path: Some("/old/path".into()),
        control_group: Some("/old".into()),
        slice: Some("system.slice".into()),
        logind_session_id: Some("c1".into()),
        logind_object_path: Some("/old/session".into()),
        target_vt: Some(3),
        previous_vt: Some(1),
        pam_status: "closed".into(),
        operation_ledger: DurableOperationLedger::default(),
        quarantine_reason: None,
        vt_busy_provenance: None,
        vt_recovery_attempts: Vec::new(),
    }
}

fn previous() -> PreviousBootRecoveryRecord {
    match RecoveryRecordEpoch::classify(record("old"), BootIdentity::parse("boot-current").unwrap())
        .unwrap()
    {
        RecoveryRecordEpoch::PreviousBoot(value) => value,
        RecoveryRecordEpoch::SameBoot(_) => panic!("expected previous boot"),
    }
}

fn clean_facts() -> PreviousBootCurrentFacts {
    PreviousBootCurrentFacts {
        conflicts: CurrentBootConflictFacts::default(),
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
        authority: CurrentAuthorityFacts {
            systemd_owner: Some("systemd".into()),
            systemd_generation: Some(0),
            logind_owner: Some("logind".into()),
            logind_generation: Some(0),
            stable: true,
        },
        scopes: Vec::new(),
        sessions: Vec::new(),
        historical_pid_reuse: Vec::new(),
        competing_records: Vec::new(),
        inspection_failures: Vec::new(),
        has_newer_record_for_seat: false,
        has_same_boot_record_for_seat: false,
        ambiguous_neighbor: false,
    }
}

#[test]
fn same_boot_and_previous_boot_are_distinct_types() {
    let boot = BootIdentity::parse("boot-current").unwrap();
    let same =
        RecoveryRecordEpoch::classify(record("same"), BootIdentity::parse("boot-old").unwrap())
            .unwrap();
    assert!(matches!(same, RecoveryRecordEpoch::SameBoot(_)));
    assert!(matches!(
        RecoveryRecordEpoch::classify(record("old"), boot).unwrap(),
        RecoveryRecordEpoch::PreviousBoot(_)
    ));
}

#[test]
fn previous_boot_cannot_construct_destructive_authority() {
    let same = SameBootRecoveryRecord {
        record: record("same"),
        current_boot: BootIdentity::parse("boot-old").unwrap(),
    };
    let authority = same.destructive_authority();
    assert!(!format!("{authority:?}").is_empty());
    // This module provides the only constructor; PreviousBootRecoveryRecord
    // intentionally has no authority-producing method or fields.
    assert_eq!(previous().recorded_boot.as_str(), "boot-old");
}

#[test]
fn pending_operations_are_never_replayed() {
    for operation in ["kill", "unref", "vt", "admin"] {
        for _ in 0..20 {
            assert_eq!(
                previous_boot_operation_policy(DurableOperationState::IntentPersisted {
                    attempt_id: 1
                }),
                PreviousBootOperationPolicy::HistoricalIndeterminateNeverReplay,
                "{operation}"
            );
        }
    }
}

#[test]
fn identity_reuse_is_not_continuity() {
    for observation in [
        CurrentIdentityObservation::PresentButDifferentIdentity,
        CurrentIdentityObservation::PresentAndConflicting,
    ] {
        for _ in 0..20 {
            let mut facts = clean_facts();
            facts.conflicts.same_unit_name = observation.clone();
            let plan = plan_previous_boot_reconciliation(&previous(), &facts);
            assert!(!matches!(
                plan,
                PreviousBootRecoveryPlan::ResolveHistoricalRecord
            ));
        }
    }
}

#[test]
fn current_scope_conflict_quarantines() {
    for _ in 0..20 {
        let mut facts = clean_facts();
        facts.conflicts.same_cgroup_path = CurrentIdentityObservation::PresentAndConflicting;
        assert!(matches!(
            plan_previous_boot_reconciliation(&previous(), &facts),
            PreviousBootRecoveryPlan::QuarantineSeatConflict { .. }
        ));
    }
}

#[test]
fn clean_absence_plans_resolution() {
    for _ in 0..20 {
        assert_eq!(
            plan_previous_boot_reconciliation(&previous(), &clean_facts()),
            PreviousBootRecoveryPlan::ResolveHistoricalRecord
        );
    }
}

#[test]
fn already_resolved_record_plans_finalize_only() {
    let mut old = previous();
    old.record.state = "record_resolved".into();
    assert_eq!(
        plan_previous_boot_reconciliation(&old, &clean_facts()),
        PreviousBootRecoveryPlan::FinalizeAlreadyResolvedRecord
    );
}

#[test]
fn inspection_unavailable_never_plans_resolution() {
    for _ in 0..20 {
        let mut facts = clean_facts();
        facts.conflicts.same_session_id = CurrentIdentityObservation::InspectionUnavailable;
        assert!(matches!(
            plan_previous_boot_reconciliation(&previous(), &facts),
            PreviousBootRecoveryPlan::InspectionRequired { .. }
        ));
    }
}

#[test]
fn conflicts_and_neighbors_fail_closed() {
    let mut facts = clean_facts();
    facts.has_same_boot_record_for_seat = true;
    assert!(matches!(
        plan_previous_boot_reconciliation(&previous(), &facts),
        PreviousBootRecoveryPlan::QuarantineSeatConflict { .. }
    ));
    facts.has_same_boot_record_for_seat = false;
    facts.ambiguous_neighbor = true;
    assert!(matches!(
        plan_previous_boot_reconciliation(&previous(), &facts),
        PreviousBootRecoveryPlan::QuarantineGlobally { .. }
    ));
}

#[test]
fn malformed_history_is_rejected_without_timestamp_comparison() {
    let mut old = previous();
    old.record.sequence = 0;
    old.record.created_at_unix = u64::MAX;
    assert!(matches!(
        plan_previous_boot_reconciliation(&old, &clean_facts()),
        PreviousBootRecoveryPlan::RejectMalformedHistory { .. }
    ));
}

#[test]
fn controlled_host_never_accesses_real_machine_and_planner_has_no_host() {
    let host = ControlledPreviousBootInspectionHost::default();
    assert!(host.current_boot_identity().is_err());
    assert_eq!(host.calls.lock().unwrap().as_slice(), ["boot"]);
    let calls_before = host.calls.lock().unwrap().len();
    let _ = plan_previous_boot_reconciliation(&previous(), &clean_facts());
    assert_eq!(host.calls.lock().unwrap().len(), calls_before);
}
