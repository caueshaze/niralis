use super::*;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub(super) fn write_control_file(path: &Path, stage: &str) -> io::Result<()> {
    write_control(path, Some(stage))
}

pub(super) fn clear_control_file(path: &Path) -> io::Result<()> {
    write_control(path, None)
}

pub(super) fn read_required_control_file(
    path: &Path,
) -> io::Result<PhysicalPreviousBootSmokeFailpoint> {
    read_optional_control_file(path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "physical PreviousBoot smoke failpoint is not armed",
        )
    })
}

pub(super) fn read_optional_control_file(
    path: &Path,
) -> io::Result<Option<PhysicalPreviousBootSmokeFailpoint>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || (!cfg!(test) && metadata.uid() != 0)
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "physical PreviousBoot smoke control file is unsafe",
        ));
    }
    let value = fs::read_to_string(path)?;
    if value.is_empty() {
        return Ok(None);
    }
    let stage = value
        .strip_prefix("NIRALIS_PREVIOUS_BOOT_FAILPOINT=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid physical PreviousBoot smoke control file",
            )
        })?;
    PhysicalPreviousBootSmokeFailpoint::parse(stage).map(Some)
}

fn write_control(path: &Path, stage: Option<&str>) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "physical PreviousBoot smoke control path",
        )
    })?;
    let temporary = parent.join(".failpoint.env.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)?;
    if let Some(stage) = stage {
        writeln!(file, "NIRALIS_PREVIOUS_BOOT_FAILPOINT={stage}")?;
    }
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    sync_directory(parent)
}
