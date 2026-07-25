#[cfg(all(test, feature = "supervisor-test-fixtures"))]
mod tests {
    use super::*;
    #[test]
    fn controlled_host_never_falls_back_to_linux() {
        let provenance = crate::VtBusyProvenance {
            target_vt: 2,
            observed_active_vt: Some(7),
            target_is_foreground: Some(false),
            target_device: None,
            visible_holders: Vec::new(),
            holders_truncated: false,
            inspection_failures: Vec::new(),
            classification: crate::VtBusyClassification::KernelBusyUnattributed,
            captured_at_boottime_ns: 1,
        };
        let host = ControlledRecoveryAdminHost {
            boundary: RecoveryAdminBoundaryFacts::Absent,
            vt: SupervisorVtIdentity {
                seat: "seat0".into(),
                number: 2,
                previous: PreviousVtIdentity { number: 7 },
                device_major: 4,
                device_minor: 2,
            },
            before: provenance.clone(),
            after: provenance,
            disallocate: Err(SupervisorRecoveryError::VtDisallocateBusy),
            runtime: Ok(()),
            events: std::sync::Mutex::new(Vec::new()),
        };
        assert!(matches!(
            host.disallocate_vt_once(2),
            Err(SupervisorRecoveryError::VtDisallocateBusy)
        ));
        assert_eq!(
            host.events(),
            vec![ControlledRecoveryAdminEvent::DisallocateVtOnce]
        );
    }
}
