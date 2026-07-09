mod auth;
mod directories;
mod tracking;

pub(super) use auth::CountingAuthenticator;
pub(super) use directories::{StubSessionDirectory, StubUserDirectory};
use niralis_auth::MockAuthenticator;
use niralis_protocol::{NiralisRequest, SessionInfo, SessionKind};
use niralis_session::MockSessionLauncher;
pub(super) use tracking::{
    CountingLoginBackend, CountingSessionLauncher, TrackingAuthenticator, TrackingSessionLauncher,
};

use crate::config::Config;
use crate::handler::DaemonHandler;
use crate::login_backend::LocalLoginBackend;

pub(super) fn handler() -> DaemonHandler<
    LocalLoginBackend<MockAuthenticator, MockSessionLauncher>,
    StubUserDirectory,
    StubSessionDirectory,
> {
    DaemonHandler::new(
        Config::default(),
        LocalLoginBackend::new(MockAuthenticator, MockSessionLauncher),
        StubUserDirectory::with_users(vec![niralis_protocol::UserInfo {
            uid: 1000,
            username: "test".to_owned(),
            display_name: "Test User".to_owned(),
        }]),
        StubSessionDirectory::with_sessions(vec![niri_session()]),
    )
}

pub(super) fn test_config(max_attempts: u32, cooldown_seconds: u64) -> Config {
    let mut config = Config::default();
    config.auth.max_attempts = max_attempts;
    config.auth.cooldown_seconds = cooldown_seconds;
    config
}

pub(super) fn login_request(password: &str, session: &str) -> NiralisRequest {
    NiralisRequest::Login {
        username: "test".to_owned(),
        password: password.to_owned(),
        session: session.to_owned(),
    }
}

pub(super) fn niri_session() -> SessionInfo {
    SessionInfo {
        id: "niri".to_owned(),
        name: "Niri".to_owned(),
        kind: SessionKind::Wayland,
    }
}
