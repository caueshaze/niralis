use std::time::Instant;

use niralis_discovery::{SessionDirectory, UserDirectory};
use niralis_protocol::NiralisResponse;
use tracing::{debug, info};
use zeroize::Zeroizing;

use super::DaemonHandler;
use crate::login_backend::{LoginAttempt, LoginBackend, LoginBackendError};

pub(super) fn handle_login<L, U, D>(
    handler: &DaemonHandler<L, U, D>,
    username: String,
    password: String,
    session: String,
) -> NiralisResponse
where
    L: LoginBackend,
    U: UserDirectory,
    D: SessionDirectory,
{
    let password = Zeroizing::new(password);

    if is_rate_limited(handler, &username) {
        info!(username = %username, "login rejected by rate limit");
        return login_failed();
    }

    let Some(session) = (match handler.session_directory.find_session(&session) {
        Ok(session) => session,
        Err(error) => return super::discovery_error_response("sessions", error),
    }) else {
        info!(username = %username, "requested session is unavailable");
        return session_unavailable();
    };

    match handler.login_backend.login(LoginAttempt {
        username: username.clone(),
        password,
        session: session.clone(),
    }) {
        Ok(_started) => {
            reset_rate_limit(handler, &username);
            NiralisResponse::LoginOk { session }
        }
        Err(LoginBackendError::AuthenticationFailed) => {
            record_login_failure(handler, &username);
            login_failed()
        }
        Err(LoginBackendError::AuthenticatedSessionFailed) => {
            reset_rate_limit(handler, &username);
            NiralisResponse::Error {
                message: "failed to start session".to_owned(),
            }
        }
        Err(LoginBackendError::InfrastructureFailed) => NiralisResponse::Error {
            message: "failed to start session".to_owned(),
        },
    }
}

pub(super) fn login_failed() -> NiralisResponse {
    NiralisResponse::LoginFailed {
        message: "login failed".to_owned(),
    }
}

pub(super) fn session_unavailable() -> NiralisResponse {
    NiralisResponse::SessionUnavailable {
        message: "session unavailable".to_owned(),
    }
}

fn is_rate_limited<L, U, D>(handler: &DaemonHandler<L, U, D>, username: &str) -> bool {
    match handler.rate_limiter.lock() {
        Ok(mut limiter) => limiter.is_limited(username, Instant::now()),
        Err(_) => {
            debug!("login rate limiter mutex is poisoned");
            true
        }
    }
}

fn record_login_failure<L, U, D>(handler: &DaemonHandler<L, U, D>, username: &str) {
    match handler.rate_limiter.lock() {
        Ok(mut limiter) => limiter.record_failure(username, Instant::now()),
        Err(_) => debug!("login rate limiter mutex is poisoned"),
    }
}

fn reset_rate_limit<L, U, D>(handler: &DaemonHandler<L, U, D>, username: &str) {
    match handler.rate_limiter.lock() {
        Ok(mut limiter) => limiter.reset(username),
        Err(_) => debug!("login rate limiter mutex is poisoned"),
    }
}
