use std::sync::atomic::{AtomicUsize, Ordering};

struct SacrificialRecoveryAdminHost {
    target: u32,
    previous: u32,
    disallocate_calls: AtomicUsize,
}

impl crate::launcher::recovery_admin_host::RecoveryAdminHost for SacrificialRecoveryAdminHost {
    fn inspect_boundary(
        &self,
        _: &PersistentRecoveryRecord,
    ) -> crate::launcher::recovery_admin_host::RecoveryAdminBoundaryFacts {
        crate::launcher::recovery_admin_host::RecoveryAdminBoundaryFacts::Absent
    }

    fn inspect_vt(&self, _: &PersistentRecoveryRecord, target_vt: u32) -> crate::VtBusyProvenance {
        inspect_vt_busy(target_vt, &[])
    }

    fn persisted_vt_identity(
        &self,
        _: &PersistentRecoveryRecord,
    ) -> Result<SupervisorVtIdentity, SupervisorRecoveryError> {
        Ok(SupervisorVtIdentity {
            seat: "seat0".to_owned(),
            number: self.target,
            previous: PreviousVtIdentity {
                number: self.previous,
            },
            device_major: 4,
            device_minor: self.target,
        })
    }

    fn disallocate_vt_once(&self, target_vt: u32) -> Result<(), SupervisorRecoveryError> {
        self.disallocate_calls.fetch_add(1, Ordering::SeqCst);
        disallocate_virtual_terminal_once(target_vt)
    }

    fn runtime_release(&self, _: &PersistentRecoveryRecord) -> Result<(), SupervisorRecoveryError> {
        Ok(())
    }
}

fn quarantined_admin_record(
    target: u32,
    previous: u32,
    provenance: crate::VtBusyProvenance,
) -> PersistentRecoveryRecord {
    let boot = current_boot_id().expect("boot id");
    PersistentRecoveryRecord {
        format_version: RECOVERY_FORMAT_VERSION,
        lifecycle_id: "sacrificial-vt".to_owned(),
        sequence: 1,
        created_at_unix: 1,
        created_boot_id: boot.clone(),
        last_updated_boot_id: boot,
        state: "quarantined".to_owned(),
        uid: 0,
        gid: 0,
        username: "fixture".to_owned(),
        session_name: "fixture".to_owned(),
        seat: "seat0".to_owned(),
        worker_pid: u32::MAX,
        worker_starttime: Some(1),
        worker_executable: Some((1, 1)),
        worker_cgroup: None,
        launcher_pid: u32::MAX - 1,
        launcher_starttime: Some(1),
        launcher_executable: Some((1, 1)),
        leader_pid: None,
        leader_starttime: None,
        leader_executable: None,
        payload_unit: None,
        transient: Some(true),
        invocation_id: Some("00000000000000000000000000000000".to_owned()),
        object_path: None,
        control_group: None,
        slice: None,
        logind_session_id: Some("fixture-gone".to_owned()),
        logind_object_path: None,
        target_vt: Some(target),
        previous_vt: Some(previous),
        pam_status: "fixture".to_owned(),
        operation_ledger: DurableOperationLedger {
            payload_kill: DurableOperationState::Confirmed { attempt_id: 1 },
            supervisor_unref: DurableOperationState::Confirmed { attempt_id: 2 },
            ..Default::default()
        },
        quarantine_reason: Some("vt_disallocate_busy".to_owned()),
        vt_busy_provenance: Some(provenance),
        vt_recovery_attempts: Vec::new(),
    }
}
