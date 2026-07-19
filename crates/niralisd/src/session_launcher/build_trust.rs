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
        validate_trusted_executable(&config.session.probe_path, ExecutableRole::SessionProbe)?;
    }
    new_worker_launcher(
        config.session.worker_path.clone(),
        config.session.child_path.clone(),
        config.session.probe_path.clone(),
        Duration::from_secs(config.session.worker_timeout_seconds),
        real_graphical_gate_environment(),
    )
    .map_err(|error| map_worker_launcher_error(error, &config.session.worker_path))
}

fn map_worker_launcher_error(
    error: niralis_session::SessionError,
    worker_path: &Path,
) -> NiralisdError {
    match error {
        niralis_session::SessionError::PersistentRecoveryUnavailable => {
            NiralisdError::PersistentRecoveryUnavailable
        }
        _ => NiralisdError::InvalidWorkerPath(worker_path.to_path_buf()),
    }
}

#[cfg(test)]
fn new_worker_launcher(
    worker_path: std::path::PathBuf,
    child_path: std::path::PathBuf,
    probe_path: std::path::PathBuf,
    timeout: Duration,
    environment: Vec<(String, String)>,
) -> std::result::Result<WorkerSessionLauncher, niralis_session::SessionError> {
    WorkerSessionLauncher::new(worker_path, child_path, probe_path, timeout, environment)
}

#[cfg(not(test))]
fn new_worker_launcher(
    worker_path: std::path::PathBuf,
    child_path: std::path::PathBuf,
    probe_path: std::path::PathBuf,
    timeout: Duration,
    environment: Vec<(String, String)>,
) -> std::result::Result<WorkerSessionLauncher, niralis_session::SessionError> {
    WorkerSessionLauncher::new_persistent(worker_path, child_path, probe_path, timeout, environment)
}

fn real_graphical_gate_environment() -> Vec<(String, String)> {
    const ALLOW: &str = "NIRALIS_ALLOW_REAL_GRAPHICAL_SESSION";
    const SESSION: &str = "NIRALIS_REAL_GRAPHICAL_SESSION";
    const WATCHDOG: &str = "NIRALIS_REAL_GRAPHICAL_SMOKE_MAX_SECONDS";

    let (Ok(allow), Ok(session), Ok(watchdog)) = (
        std::env::var(ALLOW),
        std::env::var(SESSION),
        std::env::var(WATCHDOG),
    ) else {
        return Vec::new();
    };
    if allow != "1"
        || session.is_empty()
        || session.len() > 128
        || watchdog
            .parse::<u64>()
            .ok()
            .filter(|seconds| (1..=3600).contains(seconds))
            .is_none()
    {
        return Vec::new();
    }
    vec![
        (ALLOW.to_owned(), allow),
        (SESSION.to_owned(), session),
        (WATCHDOG.to_owned(), watchdog),
    ]
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
    SessionProbe,
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
        ExecutableRole::SessionProbe => NiralisdError::InvalidSessionProbePath(path.to_path_buf()),
    }
}

fn unavailable(path: &Path, role: ExecutableRole) -> NiralisdError {
    match role {
        ExecutableRole::SessionWorker => NiralisdError::WorkerUnavailable(path.to_path_buf()),
        ExecutableRole::SessionChild => NiralisdError::SessionChildUnavailable(path.to_path_buf()),
        ExecutableRole::SessionProbe => NiralisdError::SessionProbeUnavailable(path.to_path_buf()),
    }
}

fn untrusted(path: &Path, role: ExecutableRole) -> NiralisdError {
    match role {
        ExecutableRole::SessionWorker => NiralisdError::WorkerUntrusted(path.to_path_buf()),
        ExecutableRole::SessionChild => NiralisdError::SessionChildUntrusted(path.to_path_buf()),
        ExecutableRole::SessionProbe => NiralisdError::SessionProbeUntrusted(path.to_path_buf()),
    }
}

fn has_trusted_owner_and_permissions(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & (0o022 | 0o6000) == 0
}
