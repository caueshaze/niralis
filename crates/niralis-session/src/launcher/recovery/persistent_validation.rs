use super::*;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub(crate) fn validate_lifecycle_id(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.as_bytes().contains(&0)
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid lifecycle id",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn create_secure_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != 0 && !allow_non_root_test_storage()
        || metadata.permissions().mode() & 0o077 != 0 && !allow_non_root_test_storage()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "recovery directory is not secure",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

pub(crate) fn create_lock_parent(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 && !allow_non_root_test_storage() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "recovery lock parent is not secure",
        ));
    }
    Ok(())
}

pub(crate) fn load_records(
    directory: &Path,
) -> io::Result<(BTreeMap<String, PersistentRecoveryRecord>, bool)> {
    let mut result = BTreeMap::new();
    let mut quarantined = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let name = entry.file_name();
        if !name.to_string_lossy().ends_with(".json") {
            continue;
        }
        if !ty.is_file() {
            quarantined = true;
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.uid() != 0 && !allow_non_root_test_storage()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_RECOVERY_RECORD_BYTES
        {
            quarantined = true;
            continue;
        }
        let mut file = File::open(entry.path())?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        let Ok(record) = serde_json::from_slice::<PersistentRecoveryRecord>(&bytes) else {
            quarantined = true;
            continue;
        };
        if validate_record(&record).is_err()
            || result.insert(record.lifecycle_id.clone(), record).is_some()
        {
            quarantined = true;
        }
    }
    let too_many = result.len() > MAX_RECOVERY_RECORDS;
    Ok((result, quarantined || too_many))
}

pub(crate) fn validate_record(record: &PersistentRecoveryRecord) -> io::Result<()> {
    if record.format_version != RECOVERY_FORMAT_VERSION
        || record.lifecycle_id.is_empty()
        || record.sequence == 0
        || record.created_boot_id.is_empty()
        || record.state.is_empty()
        || record.seat.is_empty()
        || record.worker_pid == 0
        || record.launcher_pid == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid recovery record",
        ));
    }
    validate_lifecycle_id(&record.lifecycle_id)
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub(crate) fn allow_non_root_test_storage() -> bool {
    cfg!(test) || cfg!(feature = "supervisor-test-fixtures")
}
