use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use niralis_session::{MockSessionLauncher, SessionLauncher, WorkerSessionLauncher};

use crate::config::{AuthBackend, Config, SessionLauncherBackend};
use crate::error::{NiralisdError, Result};

pub fn build_session_launcher(config: &Config) -> Result<Box<dyn SessionLauncher>> {
    match config.session.launcher {
        SessionLauncherBackend::Mock => Ok(Box::new(MockSessionLauncher)),
        SessionLauncherBackend::Worker => {
            validate_worker_timeout(config.session.worker_timeout_seconds)?;
            validate_worker_binary(config)?;
            WorkerSessionLauncher::new(
                config.session.worker_path.clone(),
                Duration::from_secs(config.session.worker_timeout_seconds),
            )
            .map(|launcher| Box::new(launcher) as Box<dyn SessionLauncher>)
            .map_err(|_| NiralisdError::InvalidWorkerPath(config.session.worker_path.clone()))
        }
    }
}

fn validate_worker_timeout(timeout_seconds: u64) -> Result<()> {
    if (1..=60).contains(&timeout_seconds) {
        Ok(())
    } else {
        Err(NiralisdError::InvalidWorkerTimeout(timeout_seconds))
    }
}

fn validate_worker_binary(config: &Config) -> Result<()> {
    let path = &config.session.worker_path;
    if !path.is_absolute() {
        return Err(NiralisdError::InvalidWorkerPath(path.to_path_buf()));
    }

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| NiralisdError::WorkerUnavailable(path.to_path_buf()))?;
    if metadata.file_type().is_symlink() {
        return Err(NiralisdError::WorkerUntrusted(path.to_path_buf()));
    }
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(NiralisdError::WorkerUnavailable(path.to_path_buf()));
    }
    if matches!(config.auth.backend, AuthBackend::Pam) {
        validate_trusted_path(path)?;
    }

    Ok(())
}

fn validate_trusted_path(path: &Path) -> Result<()> {
    validate_trusted_node(path, true)?;

    let mut current = path.parent();
    while let Some(parent) = current {
        validate_trusted_node(parent, false)?;
        current = parent.parent();
    }

    Ok(())
}

fn validate_trusted_node(path: &Path, expect_file: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| NiralisdError::WorkerUnavailable(path.to_path_buf()))?;
    if metadata.file_type().is_symlink() {
        return Err(NiralisdError::WorkerUntrusted(path.to_path_buf()));
    }
    if expect_file && !metadata.is_file() {
        return Err(NiralisdError::WorkerUnavailable(path.to_path_buf()));
    }
    if !expect_file && !metadata.is_dir() {
        return Err(NiralisdError::WorkerUnavailable(path.to_path_buf()));
    }
    if !has_trusted_owner_and_permissions(metadata.uid(), metadata.permissions().mode()) {
        return Err(NiralisdError::WorkerUntrusted(path.to_path_buf()));
    }
    Ok(())
}

fn has_trusted_owner_and_permissions(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn rejects_relative_worker_path() {
        let mut config = Config::default();
        config.session.launcher = SessionLauncherBackend::Worker;
        config.session.worker_path = "relative-worker".into();

        let error = match build_session_launcher(&config) {
            Ok(_) => panic!("relative path should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, NiralisdError::InvalidWorkerPath(_)));
    }

    #[test]
    fn rejects_missing_worker_binary() {
        let mut config = Config::default();
        config.session.launcher = SessionLauncherBackend::Worker;
        config.session.worker_path = "/missing/niralis-session-worker".into();

        let error = match build_session_launcher(&config) {
            Ok(_) => panic!("missing worker should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, NiralisdError::WorkerUnavailable(_)));
    }

    #[test]
    fn accepts_executable_worker_binary() {
        let dir = tempdir().expect("tempdir should exist");
        let path = dir.path().join("worker");
        std::fs::write(&path, b"binary").expect("worker should be written");
        let mut permissions = std::fs::metadata(&path)
            .expect("metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("permissions should apply");

        let mut config = Config::default();
        config.session.launcher = SessionLauncherBackend::Worker;
        config.session.worker_path = path;
        config.auth.backend = AuthBackend::Mock;

        build_session_launcher(&config).expect("executable worker should pass validation");
    }

    #[test]
    fn rejects_zero_worker_timeout() {
        let mut config = Config::default();
        config.session.launcher = SessionLauncherBackend::Worker;
        config.session.worker_timeout_seconds = 0;

        let error = match build_session_launcher(&config) {
            Ok(_) => panic!("zero timeout should fail"),
            Err(error) => error,
        };
        assert!(matches!(error, NiralisdError::InvalidWorkerTimeout(0)));
    }

    #[test]
    fn rejects_symlink_worker_in_pam_mode() {
        let dir = tempdir().expect("tempdir should exist");
        let worker = dir.path().join("worker");
        let link = dir.path().join("worker-link");
        std::fs::write(&worker, b"binary").expect("worker should be written");
        std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o755))
            .expect("permissions should apply");
        std::os::unix::fs::symlink(&worker, &link).expect("symlink should be created");

        let mut config = Config::default();
        config.session.launcher = SessionLauncherBackend::Worker;
        config.session.worker_path = link;
        config.auth.backend = AuthBackend::Pam;

        let error = match build_session_launcher(&config) {
            Ok(_) => panic!("symlink should fail in pam mode"),
            Err(error) => error,
        };
        assert!(matches!(error, NiralisdError::WorkerUntrusted(_)));
    }

    #[test]
    fn rejects_untrusted_permissions_in_pam_mode() {
        assert!(!has_trusted_owner_and_permissions(0, 0o777));
    }

    #[test]
    fn rejects_non_root_owned_worker_in_trust_policy() {
        assert!(!has_trusted_owner_and_permissions(1000, 0o755));
    }

    #[test]
    fn accepts_root_owned_non_writable_worker_in_trust_policy() {
        assert!(has_trusted_owner_and_permissions(0, 0o755));
    }
}
