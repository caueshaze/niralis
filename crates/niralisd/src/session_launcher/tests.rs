
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

    #[test]
    fn reports_persistent_ledger_failure_without_claiming_worker_path_is_invalid() {
        let error = map_worker_launcher_error(
            niralis_session::SessionError::PersistentRecoveryUnavailable,
            Path::new("/usr/libexec/niralis-session-worker"),
        );
        assert!(matches!(error, NiralisdError::PersistentRecoveryUnavailable));
    }
}
