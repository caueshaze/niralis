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
    current_boot: Option<&BootIdentity>,
) -> io::Result<(
    BTreeMap<String, PersistentRecoveryRecord>,
    Vec<DurableRecoveryRecordReadResult>,
    bool,
)> {
    persistent_taxonomy_is_complete();
    let mut result = BTreeMap::new();
    let mut read_results = Vec::new();
    let mut quarantined = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let name = entry.file_name();
        let path = entry.path();
        if !name.to_string_lossy().ends_with(".json") {
            continue;
        }
        if !ty.is_file() {
            read_results.push(DurableRecoveryRecordReadResult::UnsafeMetadata {
                path,
                reason: if ty.is_symlink() {
                    UnsafeMetadataReason::Symlink
                } else {
                    UnsafeMetadataReason::NonRegularFile
                },
            });
            quarantined = true;
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.uid() != 0 && !allow_non_root_test_storage() {
            read_results.push(DurableRecoveryRecordReadResult::UnsafeMetadata {
                path,
                reason: UnsafeMetadataReason::WrongOwner,
            });
            quarantined = true;
            continue;
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            read_results.push(DurableRecoveryRecordReadResult::UnsafeMetadata {
                path,
                reason: UnsafeMetadataReason::UnsafeMode,
            });
            quarantined = true;
            continue;
        }
        if metadata.len() > MAX_RECOVERY_RECORD_BYTES {
            read_results.push(DurableRecoveryRecordReadResult::Corrupted {
                path,
                reason: CorruptionReason::Oversized,
            });
            quarantined = true;
            continue;
        }
        if metadata.nlink() != 1 {
            read_results.push(DurableRecoveryRecordReadResult::UnsafeMetadata {
                path,
                reason: UnsafeMetadataReason::LinkCount,
            });
            quarantined = true;
            continue;
        }
        let file = File::open(entry.path())?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_RECOVERY_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECOVERY_RECORD_BYTES {
            read_results.push(DurableRecoveryRecordReadResult::Corrupted {
                path,
                reason: CorruptionReason::Truncated,
            });
            quarantined = true;
            continue;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            read_results.push(DurableRecoveryRecordReadResult::Corrupted {
                path,
                reason: CorruptionReason::InvalidJson,
            });
            quarantined = true;
            continue;
        };
        let Some(version) = value
            .get("format_version")
            .and_then(serde_json::Value::as_u64)
        else {
            read_results.push(DurableRecoveryRecordReadResult::Corrupted {
                path,
                reason: CorruptionReason::MissingRequiredField,
            });
            quarantined = true;
            continue;
        };
        if version > u64::from(RECOVERY_FORMAT_VERSION) {
            read_results
                .push(DurableRecoveryRecordReadResult::UnsupportedVersion { path, version });
            quarantined = true;
            continue;
        }
        let Ok(record) = serde_json::from_value::<PersistentRecoveryRecord>(value) else {
            read_results.push(DurableRecoveryRecordReadResult::Corrupted {
                path,
                reason: CorruptionReason::InvalidOperationLedger,
            });
            quarantined = true;
            continue;
        };
        if result.contains_key(&record.lifecycle_id) {
            read_results.push(DurableRecoveryRecordReadResult::IdentityMismatch {
                path,
                reason: RecordIdentityMismatch::DuplicateRecordId,
            });
            quarantined = true;
            continue;
        }
        let expected_name = format!("{}.json", record.lifecycle_id);
        if name != std::ffi::OsString::from(expected_name) {
            read_results.push(DurableRecoveryRecordReadResult::IdentityMismatch {
                path,
                reason: RecordIdentityMismatch::FilenameRecordId,
            });
            quarantined = true;
            continue;
        }
        if let Err(error) = validate_record(&record) {
            let reason = if error.to_string().contains("boot") {
                CorruptionReason::InvalidBootId
            } else if record.sequence == 0 {
                CorruptionReason::InvalidNumericRange
            } else {
                CorruptionReason::MissingRequiredField
            };
            read_results.push(DurableRecoveryRecordReadResult::Corrupted { path, reason });
            quarantined = true;
            continue;
        }
        let violations = validate_historical_record(&record);
        if !violations.is_empty() {
            read_results.push(
                DurableRecoveryRecordReadResult::HistoricalInvariantViolation { path, violations },
            );
            quarantined = true;
            continue;
        }
        let classified = match current_boot {
            Some(current) if record.created_boot_id == current.as_str() => {
                DurableRecoveryRecordReadResult::ValidSameBoot { path, record }
            }
            Some(_) => DurableRecoveryRecordReadResult::ValidPreviousBoot { path, record },
            None => {
                read_results.push(DurableRecoveryRecordReadResult::Corrupted {
                    path,
                    reason: CorruptionReason::InvalidBootId,
                });
                quarantined = true;
                continue;
            }
        };
        if let Some(record) = classified.record().cloned() {
            result.insert(record.lifecycle_id.clone(), record);
        }
        read_results.push(classified);
    }
    let too_many = result.len() > MAX_RECOVERY_RECORDS;
    if too_many {
        read_results.push(DurableRecoveryRecordReadResult::Corrupted {
            path: directory.to_path_buf(),
            reason: CorruptionReason::Oversized,
        });
    }
    if let Some(current_boot) = current_boot {
        let classification = classify_recovery_record_set(&read_results, current_boot);
        for reason in classification.conflicts {
            read_results.push(DurableRecoveryRecordReadResult::ConflictingRecords {
                path: directory.to_path_buf(),
                reason,
            });
        }
        if classification.global_quarantine {
            quarantined = true;
        }
    }
    Ok((result, read_results, quarantined || too_many))
}
