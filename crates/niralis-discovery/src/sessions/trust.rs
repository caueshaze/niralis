use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::{DiscoveryError, SessionSourceTrustPolicy};

pub(super) fn validate_source(
    path: &Path,
    policy: SessionSourceTrustPolicy,
    root: &Path,
) -> Result<(), DiscoveryError> {
    if !path.is_absolute() {
        return Err(DiscoveryError::UntrustedSessionSource {
            path: path.to_path_buf(),
        });
    }
    let root = std::fs::canonicalize(root).map_err(|_| DiscoveryError::UntrustedSessionSource {
        path: root.to_path_buf(),
    })?;
    let canonical =
        std::fs::canonicalize(path).map_err(|_| DiscoveryError::UntrustedSessionSource {
            path: path.to_path_buf(),
        })?;
    if !canonical.starts_with(&root) {
        return Err(DiscoveryError::UntrustedSessionSource {
            path: path.to_path_buf(),
        });
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| DiscoveryError::UntrustedSessionSource {
            path: path.to_path_buf(),
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DiscoveryError::UntrustedSessionSource {
            path: path.to_path_buf(),
        });
    }
    if policy == SessionSourceTrustPolicy::RootOwned {
        let mut current = Some(path);
        while let Some(node) = current {
            let metadata = std::fs::symlink_metadata(node).map_err(|_| {
                DiscoveryError::UntrustedSessionSource {
                    path: node.to_path_buf(),
                }
            })?;
            if metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(DiscoveryError::UntrustedSessionSource {
                    path: node.to_path_buf(),
                });
            }
            current = node.parent();
        }
    }
    Ok(())
}
