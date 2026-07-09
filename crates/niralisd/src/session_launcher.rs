use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use niralis_session::{MockSessionLauncher, SessionLauncher, WorkerSessionLauncher};

use crate::config::{Config, SessionLauncherBackend};
use crate::error::{NiralisdError, Result};

pub fn build_session_launcher(config: &Config) -> Result<Box<dyn SessionLauncher>> {
    match config.session.launcher {
        SessionLauncherBackend::Mock => Ok(Box::new(MockSessionLauncher)),
        SessionLauncherBackend::Worker => {
            validate_worker_binary(&config.session.worker_path)?;
            WorkerSessionLauncher::new(
                config.session.worker_path.clone(),
                Duration::from_secs(config.session.worker_timeout_seconds),
            )
            .map(|launcher| Box::new(launcher) as Box<dyn SessionLauncher>)
            .map_err(|_| NiralisdError::InvalidWorkerPath(config.session.worker_path.clone()))
        }
    }
}

fn validate_worker_binary(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(NiralisdError::InvalidWorkerPath(path.to_path_buf()));
    }

    let metadata = std::fs::metadata(path)
        .map_err(|_| NiralisdError::WorkerUnavailable(path.to_path_buf()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(NiralisdError::WorkerUnavailable(path.to_path_buf()));
    }

    Ok(())
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

        build_session_launcher(&config).expect("executable worker should pass validation");
    }
}
