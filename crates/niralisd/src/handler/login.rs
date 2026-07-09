use std::time::Instant;

use niralis_auth::Authenticator;
use niralis_discovery::{SessionDirectory, UserDirectory};
use niralis_protocol::NiralisResponse;
use niralis_session::{SessionLauncher, SessionRequest};
use tracing::{debug, info};

use super::DaemonHandler;

pub(super) fn handle_login<A, S, U, D>(
    handler: &DaemonHandler<A, S, U, D>,
    username: String,
    password: String,
    session: String,
) -> NiralisResponse
where
    A: Authenticator,
    S: SessionLauncher,
    U: UserDirectory,
    D: SessionDirectory,
{
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

    match handler.authenticator.authenticate(&username, &password) {
        Ok(transaction) => {
            reset_rate_limit(handler, &username);
            let user = transaction.user();
            let request = SessionRequest {
                username: user.username.clone(),
                session: session.clone(),
            };

            match handler.session_launcher.start_session(request) {
                Ok(_started) => NiralisResponse::LoginOk { session },
                Err(_) => NiralisResponse::Error {
                    message: "failed to start session".to_owned(),
                },
            }
        }
        Err(_) => {
            record_login_failure(handler, &username);
            login_failed()
        }
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

fn is_rate_limited<A, S, U, D>(handler: &DaemonHandler<A, S, U, D>, username: &str) -> bool {
    match handler.rate_limiter.lock() {
        Ok(mut limiter) => limiter.is_limited(username, Instant::now()),
        Err(_) => {
            debug!("login rate limiter mutex is poisoned");
            true
        }
    }
}

fn record_login_failure<A, S, U, D>(handler: &DaemonHandler<A, S, U, D>, username: &str) {
    match handler.rate_limiter.lock() {
        Ok(mut limiter) => limiter.record_failure(username, Instant::now()),
        Err(_) => debug!("login rate limiter mutex is poisoned"),
    }
}

fn reset_rate_limit<A, S, U, D>(handler: &DaemonHandler<A, S, U, D>, username: &str) {
    match handler.rate_limiter.lock() {
        Ok(mut limiter) => limiter.reset(username),
        Err(_) => debug!("login rate limiter mutex is poisoned"),
    }
}
