use super::*;
use std::fs::File;
use std::io;

pub(crate) fn validate_record(record: &PersistentRecoveryRecord) -> io::Result<()> {
    if !matches!(record.format_version, 1 | RECOVERY_FORMAT_VERSION)
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
    BootIdentity::parse(record.created_boot_id.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid boot id"))?;
    BootIdentity::parse(record.last_updated_boot_id.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid boot id"))?;
    validate_lifecycle_id(&record.lifecycle_id)
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub(crate) fn allow_non_root_test_storage() -> bool {
    cfg!(test) || cfg!(feature = "supervisor-test-fixtures")
}
