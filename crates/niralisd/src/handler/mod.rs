mod login;
mod rate_limit;

#[cfg(test)]
mod tests;

use std::time::Duration;

use niralis_auth::Authenticator;
use niralis_discovery::{DiscoveryError, SessionDirectory, UserDirectory};
use niralis_protocol::{DaemonStatus, NiralisRequest, NiralisResponse};
use niralis_session::SessionLauncher;

use crate::config::Config;
use rate_limit::LoginRateLimiter;

pub trait RequestHandler: Send + Sync {
    fn handle(&self, request: NiralisRequest) -> NiralisResponse;
}

#[derive(Debug)]
pub struct DaemonHandler<A, S, U, D> {
    config: Config,
    authenticator: A,
    session_launcher: S,
    user_directory: U,
    session_directory: D,
    rate_limiter: std::sync::Mutex<LoginRateLimiter>,
}

impl<A, S, U, D> DaemonHandler<A, S, U, D> {
    pub fn new(
        config: Config,
        authenticator: A,
        session_launcher: S,
        user_directory: U,
        session_directory: D,
    ) -> Self {
        let rate_limiter = LoginRateLimiter::new(
            config.auth.max_attempts,
            Duration::from_secs(config.auth.cooldown_seconds),
        );

        Self {
            config,
            authenticator,
            session_launcher,
            user_directory,
            session_directory,
            rate_limiter: std::sync::Mutex::new(rate_limiter),
        }
    }
}

impl<A, S, U, D> RequestHandler for DaemonHandler<A, S, U, D>
where
    A: Authenticator,
    S: SessionLauncher,
    U: UserDirectory,
    D: SessionDirectory,
{
    fn handle(&self, request: NiralisRequest) -> NiralisResponse {
        match request {
            NiralisRequest::Status => NiralisResponse::Status {
                status: DaemonStatus {
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    socket: self.config.daemon.socket.display().to_string(),
                    default_session: self.config.session.default.clone(),
                    greeter_user: self.config.greeter.user.clone(),
                },
            },
            NiralisRequest::GetUsers => match self.user_directory.list_users() {
                Ok(users) => NiralisResponse::Users { users },
                Err(error) => discovery_error_response("users", error),
            },
            NiralisRequest::GetSessions => match self.session_directory.list_sessions() {
                Ok(sessions) => NiralisResponse::Sessions { sessions },
                Err(error) => discovery_error_response("sessions", error),
            },
            NiralisRequest::Login {
                username,
                password,
                session,
            } => login::handle_login(self, username, password, session),
            NiralisRequest::Shutdown | NiralisRequest::Reboot => NiralisResponse::Error {
                message: "not implemented in phase 1".to_owned(),
            },
        }
    }
}

fn discovery_error_response(scope: &str, error: DiscoveryError) -> NiralisResponse {
    NiralisResponse::Error {
        message: format!("failed to discover {scope}: {error}"),
    }
}
