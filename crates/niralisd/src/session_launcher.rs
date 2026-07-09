use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use niralis_session::{MockSessionLauncher, SessionLauncher, WorkerSessionLauncher};

use crate::config::{AuthBackend, Config, SessionLauncherBackend};
use crate::error::{NiralisdError, Result};

pub fn build_session_launcher(config: &Config) -> Result<Box<dyn SessionLauncher>> {
    match config.session.launcher {
        SessionLauncherBackend::Mock => Ok(Box::new(MockSessionLauncher)),
        SessionLauncherBackend::Worker => build_worker_session_launcher(config)
            .map(|launcher| Box::new(launcher) as Box<dyn SessionLauncher>),
    }
}

pub fn build_worker_session_launcher(config: &Config) -> Result<WorkerSessionLauncher> {
    validate_worker_timeout(config.session.worker_timeout_seconds)?;
    validate_worker_binary(config)?;
    if matches!(config.auth.backend, AuthBackend::Pam) {
        validate_trusted_executable(&config.session.child_path, ExecutableRole::SessionChild)?;
    }
    WorkerSessionLauncher::new(
        config.session.worker_path.clone(),
        config.session.child_path.clone(),
        Duration::from_secs(config.session.worker_timeout_seconds),
    )
    .map_err(|_| NiralisdError::InvalidWorkerPath(config.session.worker_path.clone()))
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
    if matches!(config.auth.backend, AuthBackend::Pam) {
        validate_trusted_executable(path, ExecutableRole::SessionWorker)?;
    } else {
        validate_basic_executable(path, ExecutableRole::SessionWorker)?;
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ExecutableRole {
    SessionWorker,
    SessionChild,
}

fn validate_trusted_executable(path: &Path, role: ExecutableRole) -> Result<()> {
    validate_basic_executable(path, role)?;
    validate_trusted_node(path, true, role)?;

    let mut current = path.parent();
    while let Some(parent) = current {
        validate_trusted_node(parent, false, role)?;
        current = parent.parent();
    }

    Ok(())
}

fn validate_trusted_node(path: &Path, expect_file: bool, role: ExecutableRole) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path).map_err(|_| unavailable(path, role))?;
    if metadata.file_type().is_symlink() {
        return Err(untrusted(path, role));
    }
    if expect_file && !metadata.is_file() {
        return Err(unavailable(path, role));
    }
    if !expect_file && !metadata.is_dir() {
        return Err(unavailable(path, role));
    }
    if !has_trusted_owner_and_permissions(metadata.uid(), metadata.permissions().mode()) {
        return Err(untrusted(path, role));
    }
    Ok(())
}

fn validate_basic_executable(path: &Path, role: ExecutableRole) -> Result<()> {
    if !path.is_absolute() {
        return Err(invalid(path, role));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| unavailable(path, role))?;
    if metadata.file_type().is_symlink() {
        return Err(untrusted(path, role));
    }
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(unavailable(path, role));
    }
    Ok(())
}

fn invalid(path: &Path, role: ExecutableRole) -> NiralisdError {
    match role {
        ExecutableRole::SessionWorker => NiralisdError::InvalidWorkerPath(path.to_path_buf()),
        ExecutableRole::SessionChild => NiralisdError::InvalidSessionChildPath(path.to_path_buf()),
    }
}

fn unavailable(path: &Path, role: ExecutableRole) -> NiralisdError {
    match role {
        ExecutableRole::SessionWorker => NiralisdError::WorkerUnavailable(path.to_path_buf()),
        ExecutableRole::SessionChild => NiralisdError::SessionChildUnavailable(path.to_path_buf()),
    }
}

fn untrusted(path: &Path, role: ExecutableRole) -> NiralisdError {
    match role {
        ExecutableRole::SessionWorker => NiralisdError::WorkerUntrusted(path.to_path_buf()),
        ExecutableRole::SessionChild => NiralisdError::SessionChildUntrusted(path.to_path_buf()),
    }
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
    fn rejects_relative_session_child_path() {
        let error = validate_trusted_executable(
            Path::new("relative-session-child"),
            ExecutableRole::SessionChild,
        )
        .expect_err("relative child path should fail");
        assert!(matches!(error, NiralisdError::InvalidSessionChildPath(_)));
    }

    #[test]
    fn rejects_missing_session_child_path() {
        let error = validate_trusted_executable(
            Path::new("/missing/niralis-session-child"),
            ExecutableRole::SessionChild,
        )
        .expect_err("missing child should fail");
        assert!(matches!(error, NiralisdError::SessionChildUnavailable(_)));
    }

    #[test]
    fn accepts_root_owned_non_writable_worker_in_trust_policy() {
        assert!(has_trusted_owner_and_permissions(0, 0o755));
    }
}
