use super::*;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) fn load_records(directory: &Path) -> io::Result<BTreeMap<String, PreCommitRuntimeRecord>> {
    let mut records = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path)?;
        if bytes.len() as u64 > MAX_PRECOMMIT_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "precommit runtime record too large",
            ));
        }
        let record: PreCommitRuntimeRecord =
            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        validate_record(&record)?;
        records.insert(record.lifecycle_id.clone(), record);
    }
    Ok(records)
}

pub(crate) fn validate_record(record: &PreCommitRuntimeRecord) -> io::Result<()> {
    if record.format_version != PRECOMMIT_FORMAT_VERSION
        || record.transaction_id.is_empty()
        || record.lifecycle_id.is_empty()
        || record.transaction_id != record.lifecycle_id
        || record.admission_attempt_id == 0
        || record.seat.is_empty()
        || record.seat_generation == 0
        || record.boot_id.is_empty()
        || !matches!(
            record.stage.as_str(),
            "reserved"
                | "worker_attached"
                | "authentication_inflight"
                | "authenticated"
                | "preparing_launch"
                | "handoff_started"
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid precommit runtime record",
        ));
    }
    validate_lifecycle_id(&record.lifecycle_id)
}

pub(crate) fn validate_lifecycle_id(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid precommit lifecycle id",
        ));
    }
    Ok(())
}

pub(crate) fn create_secure_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::metadata(path)?;
    if (metadata.uid() != 0 && !allow_non_root_test_storage())
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "precommit runtime directory permissions",
        ));
    }
    Ok(())
}

pub(crate) fn create_lock_parent(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub(crate) fn allow_non_root_test_storage() -> bool {
    cfg!(test)
        || cfg!(feature = "integration-test-control")
        || cfg!(feature = "supervisor-test-fixtures")
}

pub(super) fn temporary_record_path(directory: &Path, lifecycle_id: &str) -> PathBuf {
    directory.join(format!(".{}.tmp", lifecycle_id))
}

pub(super) fn open_temporary_record(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}
