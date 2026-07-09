use std::path::PathBuf;

use crate::config::{AuthBackend, Config, SessionLauncherBackend};
use crate::error::NiralisdError;
use crate::login_backend::build_login_backend;

fn config_raw(auth_backend: &str) -> String {
    format!(
        r#"
            [daemon]
            socket = "/tmp/niralis-test/niralisd.sock"
            log_level = "debug"

            [greeter]
            command = "/usr/bin/niralis-greeter"
            user = "niralis"

            [auth]
            backend = "{auth_backend}"
            pam_service = "niralis"
            max_attempts = 5
            cooldown_seconds = 10

            [users]
            min_uid = 1000
            allow_root = false
            exclude = ["nobody"]

            [sessions]
            wayland_dirs = ["/usr/share/wayland-sessions"]
            include_x11 = false
            x11_dirs = ["/usr/share/xsessions"]
            exec_search_path = ["/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin"]

            [session]
            default = "niri"
            command = "niri-session"
            launcher = "mock"
            worker_path = "/usr/libexec/niralis-session-worker"
            worker_timeout_seconds = 5
        "#
    )
}

#[test]
fn parses_pam_backend_shape() {
    let config: Config = toml::from_str(&config_raw("pam")).expect("config should parse");

    assert_eq!(
        config.daemon.socket,
        PathBuf::from("/tmp/niralis-test/niralisd.sock")
    );
    assert_eq!(config.auth.backend, AuthBackend::Pam);
    assert_eq!(config.users.min_uid, 1000);
    assert_eq!(config.sessions.exec_search_path.len(), 4);
    assert_eq!(config.session.default, "niri");
    assert_eq!(config.session.launcher, SessionLauncherBackend::Mock);
}

#[test]
fn parses_mock_backend_shape() {
    let config: Config = toml::from_str(&config_raw("mock")).expect("config should parse");

    assert_eq!(config.auth.backend, AuthBackend::Mock);
}

#[test]
fn default_backend_is_pam() {
    assert_eq!(Config::default().auth.backend, AuthBackend::Pam);
}

#[test]
fn missing_backend_and_discovery_sections_use_defaults() {
    let raw = r#"
            [daemon]
            socket = "/tmp/niralis-test/niralisd.sock"
            log_level = "debug"

            [greeter]
            command = "/usr/bin/niralis-greeter"
            user = "niralis"

            [auth]
            pam_service = "niralis"
            max_attempts = 5
            cooldown_seconds = 10

            [session]
            default = "niri"
            command = "niri-session"
        "#;

    let config: Config = toml::from_str(raw).expect("config should parse");

    assert_eq!(config.auth.backend, AuthBackend::Pam);
    assert_eq!(config.users.min_uid, 1000);
    assert_eq!(
        config.sessions.wayland_dirs[0],
        PathBuf::from("/usr/share/wayland-sessions")
    );
    assert_eq!(config.session.launcher, SessionLauncherBackend::Mock);
    assert_eq!(
        config.session.worker_path,
        PathBuf::from("/usr/libexec/niralis-session-worker")
    );
    assert_eq!(config.session.worker_timeout_seconds, 5);
}

#[test]
fn rejects_pam_with_mock_launcher() {
    let mut config = Config::default();
    config.auth.backend = AuthBackend::Pam;
    config.session.launcher = SessionLauncherBackend::Mock;

    let error = match build_login_backend(&config) {
        Ok(_) => panic!("pam + mock should fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        NiralisdError::InvalidAuthLauncherCombination
    ));
}
