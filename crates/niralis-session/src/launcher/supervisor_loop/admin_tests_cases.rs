#[test]
fn logind_present_blocks_before_ioctl() {
    assert_boundary_fact_blocks(RecoveryAdminBoundaryFacts::LogindPresent);
}
#[test]
fn authority_changed_blocks_before_ioctl() {
    assert_boundary_fact_blocks(RecoveryAdminBoundaryFacts::AuthorityChanged);
}

#[test]
fn target_foreground_blocks_before_ioctl() {
    let mut foreground = provenance();
    foreground.observed_active_vt = Some(2);
    foreground.target_is_foreground = Some(true);
    foreground.classification = crate::VtBusyClassification::TargetStillForeground;
    let host = host_with_provenance(foreground);
    let (mut state, _) = state(host.clone());
    assert!(matches!(
        state.recovery_admin(request()).unwrap(),
        crate::RecoveryAdminResponse::Rejected { .. }
    ));
    assert!(!host
        .events()
        .contains(&ControlledRecoveryAdminEvent::DisallocateVtOnce));
}

#[test]
fn stale_record_sequence_is_rejected_before_host_access() {
    let host = host(Ok(()), Ok(()));
    let (mut state, _) = state(host.clone());
    let mut stale = request();
    if let crate::RecoveryAdminRequest::RetryVtDisallocate {
        record_sequence, ..
    } = &mut stale
    {
        *record_sequence = 0;
    }
    assert!(matches!(
        state.recovery_admin(stale).unwrap(),
        crate::RecoveryAdminResponse::Rejected { .. }
    ));
    assert!(host.events().is_empty());
}

#[test]
fn acknowledgement_requires_exact_attempt_id_without_ioctl() {
    let host = host(Ok(()), Ok(()));
    let mut persisted = record();
    persisted
        .vt_recovery_attempts
        .push(crate::VtRecoveryAttempt {
            attempt_id: 9,
            requested_by: 0,
            expected_sequence: 1,
            state: crate::VtRecoveryAttemptState::Indeterminate,
            provenance_before: provenance(),
            provenance_after: None,
        });
    let (mut state, _) = state_with(host.clone(), persisted);
    assert!(matches!(
        state.recovery_admin(request()).unwrap(),
        crate::RecoveryAdminResponse::Rejected { .. }
    ));
    assert!(host.events().is_empty());
    let mut acknowledged = request();
    if let crate::RecoveryAdminRequest::RetryVtDisallocate {
        acknowledge_indeterminate,
        ..
    } = &mut acknowledged
    {
        *acknowledge_indeterminate = Some(9);
    }
    assert!(matches!(
        state.recovery_admin(acknowledged).unwrap(),
        crate::RecoveryAdminResponse::RetryAccepted { .. }
    ));
    assert_eq!(
        host.events()
            .iter()
            .filter(|event| **event == ControlledRecoveryAdminEvent::DisallocateVtOnce)
            .count(),
        1
    );
}

#[test]
fn duplicate_request_after_ebusy_is_single_shot() {
    let host = host(Err(SupervisorRecoveryError::VtDisallocateBusy), Ok(()));
    let (mut state, _) = state(host.clone());
    assert!(matches!(
        state.recovery_admin(request()).unwrap(),
        crate::RecoveryAdminResponse::RetryAccepted { .. }
    ));
    assert!(matches!(
        state.recovery_admin(request()).unwrap(),
        crate::RecoveryAdminResponse::Rejected { .. }
    ));
    assert_eq!(
        host.events()
            .iter()
            .filter(|event| **event == ControlledRecoveryAdminEvent::DisallocateVtOnce)
            .count(),
        1
    );
}

#[test]
fn wrong_record_id_is_rejected_before_host_access() {
    let host = host(Ok(()), Ok(()));
    let (mut state, _) = state(host.clone());
    let mut request = request();
    if let crate::RecoveryAdminRequest::RetryVtDisallocate { record_id, .. } = &mut request {
        *record_id = "other".to_owned();
    }
    assert!(matches!(state.recovery_admin(request).unwrap(), crate::RecoveryAdminResponse::Rejected { .. }));
    assert!(host.events().is_empty());
}

#[test]
fn different_boot_is_rejected_before_host_access() {
    let host = host(Ok(()), Ok(()));
    let mut persisted = record();
    persisted.created_boot_id = "another-boot".to_owned();
    persisted.last_updated_boot_id = "another-boot".to_owned();
    let (mut state, _) = state_with(host.clone(), persisted);
    assert!(matches!(state.recovery_admin(request()).unwrap(), crate::RecoveryAdminResponse::Rejected { .. }));
    assert!(host.events().is_empty());
}

#[test]
fn authority_lost_and_process_reuse_block_before_ioctl() {
    assert_boundary_fact_blocks(RecoveryAdminBoundaryFacts::AuthorityLost);
    assert_boundary_fact_blocks(RecoveryAdminBoundaryFacts::ProcessIdentityReused);
}

fn holder_provenance(classification: crate::VtBusyClassification, holders: usize) -> crate::VtBusyProvenance {
    let mut value = provenance();
    value.classification = classification;
    value.visible_holders = (0..holders)
        .map(|offset| crate::VtHolderIdentity {
            pid: 100 + offset as u32,
            starttime: 10 + offset as u64,
            uid: 1000,
            fd: 7 + offset as u32,
            executable: Some(crate::ExecutableIdentity { device: 1, inode: 2 + offset as u64 }),
            cgroup: Some(format!("/fixture/{offset}")),
            session_id: None,
        })
        .collect();
    value
}

#[test]
fn visible_and_internal_holders_block_initial_ioctl() {
    for classification in [
        crate::VtBusyClassification::VisibleUserspaceHolder,
        crate::VtBusyClassification::InternalNiralisHolder,
    ] {
        let host = host_with_provenance(holder_provenance(classification, 1));
        let (mut state, _) = state(host.clone());
        assert!(matches!(state.recovery_admin(request()).unwrap(), crate::RecoveryAdminResponse::Rejected { .. }));
        assert!(!host.events().contains(&ControlledRecoveryAdminEvent::DisallocateVtOnce));
    }
}

#[test]
fn multiple_holders_are_bounded_and_preserved_in_rejection() {
    let mut value = holder_provenance(crate::VtBusyClassification::MultipleVisibleUserspaceHolders, 2);
    value.holders_truncated = true;
    let host = host_with_provenance(value);
    let (mut state, ledger) = state(host);
    assert!(matches!(state.recovery_admin(request()).unwrap(), crate::RecoveryAdminResponse::Rejected { .. }));
    let locked = ledger.lock().unwrap();
    let persisted = locked.records.get("admin-fixture").unwrap();
    let attempt = persisted.vt_recovery_attempts.last().unwrap();
    assert_eq!(attempt.provenance_before.visible_holders.len(), 2);
    assert!(attempt.provenance_before.holders_truncated);
}

#[test]
fn inspection_unavailable_never_calls_ioctl() {
    let mut value = provenance();
    value.classification = crate::VtBusyClassification::InspectionUnavailable;
    value.inspection_failures.push(crate::VtInspectionFailure::ProcEnumeration { errno: libc::EACCES });
    let host = host_with_provenance(value);
    let (mut state, _) = state(host.clone());
    assert!(matches!(state.recovery_admin(request()).unwrap(), crate::RecoveryAdminResponse::Rejected { .. }));
    assert!(!host.events().contains(&ControlledRecoveryAdminEvent::DisallocateVtOnce));
}

#[test]
fn non_ebusy_failure_is_single_shot_and_quarantined() {
    let host = host(Err(SupervisorRecoveryError::VtDisallocateFailed(libc::EPERM)), Ok(()));
    let (mut state, ledger) = state(host.clone());
    assert!(matches!(state.recovery_admin(request()).unwrap(), crate::RecoveryAdminResponse::Rejected { .. }));
    assert!(!state.admission.is_free());
    assert!(matches!(ledger.lock().unwrap().records["admin-fixture"].vt_recovery_attempts.last().unwrap().state, crate::VtRecoveryAttemptState::Failed { errno } if errno == libc::EPERM));
    assert_eq!(host.events().iter().filter(|event| **event == ControlledRecoveryAdminEvent::DisallocateVtOnce).count(), 1);
}
