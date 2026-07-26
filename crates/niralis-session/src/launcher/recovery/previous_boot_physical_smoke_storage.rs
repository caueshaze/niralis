use super::*;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub(super) fn seed_record(
    paths: &PhysicalPreviousBootSmokePaths,
    boot: String,
) -> PersistentRecoveryRecord {
    PersistentRecoveryRecord {
        format_version: RECOVERY_FORMAT_VERSION,
        lifecycle_id: paths.record_id(),
        sequence: 1,
        created_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |value| value.as_secs()),
        created_boot_id: boot.clone(),
        last_updated_boot_id: boot,
        state: "started".to_owned(),
        uid: 0,
        gid: 0,
        username: "previous-boot-smoke".to_owned(),
        session_name: "previous-boot-smoke".to_owned(),
        seat: format!("smoke-{}", paths.run_id()),
        worker_pid: u32::MAX,
        launcher_pid: u32::MAX,
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
        target_vt: None,
        previous_vt: None,
        pam_status: "physical_smoke_seed".to_owned(),
        operation_ledger: DurableOperationLedger {
            payload_kill: DurableOperationState::IntentPersisted { attempt_id: 1 },
            supervisor_unref: DurableOperationState::Indeterminate {
                attempt_id: 2,
                stage: 1,
            },
            logind_termination: DurableOperationState::IntentPersisted { attempt_id: 3 },
            selinux_restore: DurableOperationState::NotStarted,
            vt_activation: DurableOperationState::NotStarted,
            vt_disallocate: DurableOperationState::Indeterminate {
                attempt_id: 4,
                stage: 1,
            },
            runtime_release: DurableOperationState::NotStarted,
            record_resolution: DurableOperationState::NotStarted,
        },
        quarantine_reason: None,
        vt_busy_provenance: None,
        vt_recovery_attempts: Vec::new(),
    }
}

pub(super) fn only_smoke_record<'a>(
    ledger: &'a PersistentRecoveryLedger,
    paths: &PhysicalPreviousBootSmokePaths,
) -> io::Result<&'a PersistentRecoveryRecord> {
    if ledger.read_results().len() != 1 || ledger.records().count() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "physical PreviousBoot smoke ledger contains unexpected records",
        ));
    }
    let record = ledger.records().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "physical PreviousBoot smoke record is missing",
        )
    })?;
    if record.lifecycle_id != paths.record_id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "physical PreviousBoot smoke record identity mismatch",
        ));
    }
    Ok(record)
}

pub(super) fn validate_run_id(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 48
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid physical PreviousBoot smoke run id",
        ));
    }
    Ok(())
}

pub(super) fn physical_boot_id() -> io::Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    BootIdentity::parse(value.trim().to_owned())
        .map(|identity| identity.as_str().to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid current boot id"))
}

pub(super) fn reject_test_boot_override() -> io::Result<()> {
    if std::env::var_os("NIRALIS_TEST_BOOT_ID").is_some() {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "physical PreviousBoot smoke rejects NIRALIS_TEST_BOOT_ID",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn ensure_secure_root(path: &Path) -> io::Result<()> {
    if !cfg!(test) {
        let base = Path::new(SMOKE_ROOT);
        if path.parent() != Some(base) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "physical PreviousBoot smoke path escapes its fixed root",
            ));
        }
        validate_secure_directory(base)?;
        if let Err(error) = fs::create_dir(path) {
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
    } else {
        fs::create_dir_all(path)?;
    }
    validate_secure_directory_identity(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .and_then(|()| validate_secure_directory(path))
}

fn validate_secure_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    validate_secure_directory_metadata(&metadata, true)
}

fn validate_secure_directory_identity(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    validate_secure_directory_metadata(&metadata, false)
}

fn validate_secure_directory_metadata(
    metadata: &fs::Metadata,
    require_private_mode: bool,
) -> io::Result<()> {
    if !metadata.file_type().is_dir()
        || (!cfg!(test) && metadata.uid() != 0)
        || (require_private_mode && !cfg!(test) && metadata.permissions().mode() & 0o077 != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "physical PreviousBoot smoke root is unsafe",
        ));
    }
    Ok(())
}
