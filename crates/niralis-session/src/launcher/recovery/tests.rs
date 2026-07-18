use super::*;

#[cfg(test)]
mod supervisor_recovery_tests {
    use super::*;
    mod invariants;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::atomic::Ordering;

    fn identity() -> crate::PayloadScopeIdentity {
        crate::PayloadScopeIdentity {
            unit_name: "niralis-payload-0123456789abcdef0123456789abcdef.scope".to_owned(),
            invocation_id: "0123456789abcdef0123456789abcdef".to_owned(),
            expected_uid: 1000,
            logind_session_id: crate::LogindSessionId::new("c1".to_owned()).unwrap(),
        }
    }

    fn provider(mode: SupervisorFixtureBoundaryMode) -> SupervisorFixtureRecoveryProvider {
        let mut provider = SupervisorFixtureRecoveryProvider::successful();
        provider.mode = mode;
        provider.logind_already_gone = false;
        provider
    }

    fn started_record(
        provider: &SupervisorFixtureRecoveryProvider,
    ) -> SupervisorSessionRecoveryRecord {
        let session = StartedSession {
            username: "fixture-user".to_owned(),
            session: niralis_protocol::SessionInfo {
                id: "niri".to_owned(),
                name: "Niri".to_owned(),
                kind: niralis_protocol::SessionKind::Wayland,
            },
        };
        let mut record = SupervisorSessionRecoveryRecord::worker_spawned(
            "lifecycle-1".to_owned(),
            4242,
            std::process::id(),
            &session,
            PreviousVtIdentity { number: 1 },
        );
        let payload = provider
            .prepare_payload(
                &identity(),
                5252,
                4242,
                std::process::id(),
                &PreviousVtIdentity { number: 1 },
            )
            .unwrap();
        record.state = SupervisorRecoveryState::Started {
            payload,
            runtime_id: RuntimeSessionId::new("lifecycle-1".to_owned()),
        };
        record
    }

    fn killed_worker_status() -> ExitStatus {
        ExitStatus::from_raw(libc::SIGKILL)
    }

    #[test]
    fn supervisor_pin_and_leader_identity_are_prepared_before_ack() {
        let _ = SupervisorFixtureRecoveryProvider::successful();
        let source = include_str!("../launch_protocol.rs");
        let prepare = source.find("record_prepared_scope").unwrap();
        let ack = source.find("PayloadScopeRegistered").unwrap();
        let registered = source.find("mark_payload_registered").unwrap();
        assert!(prepare < ack && ack < registered);
        assert_eq!(crate::WORKER_PROTOCOL_VERSION, 12);
        assert_eq!(crate::WORKER_CONTROL_PROTOCOL_VERSION, 3);
    }

    #[test]
    fn worker_sigkill_running_is_recovered_by_supervisor() {
        let provider = provider(SupervisorFixtureBoundaryMode::PopulatedThenRecovered);
        let mut record = started_record(&provider);
        let outcome = SupervisorEmergencyRecoveryCoordinator::new(&provider)
            .recover(&mut record, killed_worker_status());
        assert!(matches!(
            outcome,
            SupervisorEmergencyRecoveryOutcome::Recovered { .. }
        ));
        assert_eq!(provider.counters.emergency_kills.load(Ordering::SeqCst), 1);
        assert_eq!(provider.counters.proofs.load(Ordering::SeqCst), 1);
        assert_eq!(provider.counters.unrefs.load(Ordering::SeqCst), 1);
        assert_eq!(
            provider.counters.logind_terminations.load(Ordering::SeqCst),
            1
        );
        assert_eq!(provider.counters.vt_recoveries.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn worker_dies_with_boundary_already_empty_without_emergency_kill() {
        let provider = provider(SupervisorFixtureBoundaryMode::AlreadyEmpty);
        let mut record = started_record(&provider);
        let outcome = SupervisorEmergencyRecoveryCoordinator::new(&provider)
            .recover(&mut record, killed_worker_status());
        assert!(matches!(
            outcome,
            SupervisorEmergencyRecoveryOutcome::Recovered { .. }
        ));
        assert_eq!(provider.counters.emergency_kills.load(Ordering::SeqCst), 0);
        assert_eq!(provider.counters.proofs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dead_leader_with_remaining_boundary_member_forces_boundary_once() {
        let provider = provider(SupervisorFixtureBoundaryMode::PopulatedThenRecovered);
        let mut record = started_record(&provider);
        let _ = SupervisorEmergencyRecoveryCoordinator::new(&provider)
            .recover(&mut record, killed_worker_status());
        assert_eq!(provider.counters.emergency_kills.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn replacement_before_emergency_kill_quarantines_without_kill() {
        let provider = provider(SupervisorFixtureBoundaryMode::Replacement);
        let mut record = started_record(&provider);
        let outcome = SupervisorEmergencyRecoveryCoordinator::new(&provider)
            .recover(&mut record, killed_worker_status());
        assert!(matches!(
            outcome,
            SupervisorEmergencyRecoveryOutcome::Quarantined {
                reason: SupervisorRecoveryError::BoundaryIdentityChanged,
                ..
            }
        ));
        assert_eq!(provider.counters.emergency_kills.load(Ordering::SeqCst), 0);
        assert_eq!(
            provider.counters.logind_terminations.load(Ordering::SeqCst),
            0
        );
        assert_eq!(provider.counters.vt_recoveries.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn bus_loss_has_no_destructive_fallback_and_quarantines() {
        let provider = provider(SupervisorFixtureBoundaryMode::BusLoss);
        let mut record = started_record(&provider);
        let outcome = SupervisorEmergencyRecoveryCoordinator::new(&provider)
            .recover(&mut record, killed_worker_status());
        assert!(matches!(
            outcome,
            SupervisorEmergencyRecoveryOutcome::Quarantined {
                reason: SupervisorRecoveryError::BusDeliveryIndeterminate,
                ..
            }
        ));
        assert_eq!(provider.counters.emergency_kills.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn boundary_timeout_preserves_logind_and_vt_ownership() {
        let provider = provider(SupervisorFixtureBoundaryMode::Timeout);
        let mut record = started_record(&provider);
        let outcome = SupervisorEmergencyRecoveryCoordinator::new(&provider)
            .recover(&mut record, killed_worker_status());
        assert!(matches!(
            outcome,
            SupervisorEmergencyRecoveryOutcome::Quarantined {
                reason: SupervisorRecoveryError::BoundaryTimedOut,
                ..
            }
        ));
        assert_eq!(provider.counters.unrefs.load(Ordering::SeqCst), 0);
        assert_eq!(
            provider.counters.logind_terminations.load(Ordering::SeqCst),
            0
        );
        assert_eq!(provider.counters.vt_recoveries.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn selinux_restore_failure_does_not_claim_vt_or_runtime_release() {
        let mut provider = provider(SupervisorFixtureBoundaryMode::AlreadyEmpty);
        provider.vt_result = Err(SupervisorRecoveryError::SelinuxRestoreFailed(libc::EACCES));
        let mut record = started_record(&provider);
        let outcome = SupervisorEmergencyRecoveryCoordinator::new(&provider)
            .recover(&mut record, killed_worker_status());
        assert!(matches!(
            outcome,
            SupervisorEmergencyRecoveryOutcome::Quarantined {
                stage: EmergencyRecoveryStage::SelinuxTtyRestore,
                ..
            }
        ));
        assert_eq!(provider.counters.vt_recoveries.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn normal_worker_exit_has_zero_emergency_kills_and_one_unref() {
        let mut provider = provider(SupervisorFixtureBoundaryMode::AlreadyEmpty);
        provider.logind_already_gone = true;
        let mut record = started_record(&provider);
        let clean = ExitStatus::from_raw(0);
        crate::launcher::finalize_clean_worker_exit(&mut record, clean, &provider).unwrap();
        assert_eq!(provider.counters.emergency_kills.load(Ordering::SeqCst), 0);
        assert_eq!(provider.counters.unrefs.load(Ordering::SeqCst), 1);
        assert_eq!(provider.counters.vt_recoveries.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn duplicate_recovery_does_not_repeat_destructive_actions() {
        let provider = provider(SupervisorFixtureBoundaryMode::PopulatedThenRecovered);
        let mut record = started_record(&provider);
        let outcome = SupervisorEmergencyRecoveryCoordinator::new(&provider)
            .recover(&mut record, killed_worker_status());
        record.state = SupervisorRecoveryState::Recovered { outcome };
        let counters = (
            provider.counters.emergency_kills.load(Ordering::SeqCst),
            provider.counters.unrefs.load(Ordering::SeqCst),
            provider.counters.logind_terminations.load(Ordering::SeqCst),
            provider.counters.vt_recoveries.load(Ordering::SeqCst),
        );
        let second = SupervisorEmergencyRecoveryCoordinator::new(&provider)
            .recover(&mut record, killed_worker_status());
        assert!(matches!(
            second,
            SupervisorEmergencyRecoveryOutcome::Quarantined { .. }
        ));
        assert_eq!(
            counters,
            (
                provider.counters.emergency_kills.load(Ordering::SeqCst),
                provider.counters.unrefs.load(Ordering::SeqCst),
                provider.counters.logind_terminations.load(Ordering::SeqCst),
                provider.counters.vt_recoveries.load(Ordering::SeqCst),
            )
        );
    }
}
