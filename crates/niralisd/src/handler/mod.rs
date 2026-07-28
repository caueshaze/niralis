mod login;
mod rate_limit;
mod transactions;

#[cfg(test)]
mod tests;

use std::time::Duration;

use niralis_discovery::{DiscoveryError, SessionDirectory, UserDirectory};
use niralis_protocol::{DaemonStatus, NiralisRequest, NiralisResponse};

use crate::config::Config;
use crate::login_backend::LoginBackend;
use rate_limit::LoginRateLimiter;

pub trait RequestHandler: Send + Sync {
    fn handle(&self, request: NiralisRequest) -> NiralisResponse;

    fn handle_authenticated(
        &self,
        _authority: &crate::connection::GreeterConnectionAuthority,
        _request_id: u64,
        request: NiralisRequest,
    ) -> NiralisResponse {
        self.handle(request)
    }

    fn connection_closed(&self, _authority: &crate::connection::GreeterConnectionAuthority) {}

    fn cancel_authenticated(
        &self,
        _authority: &crate::connection::GreeterConnectionAuthority,
        _request_id: u64,
        _target_request_id: u64,
    ) -> NiralisResponse {
        NiralisResponse::Error {
            message: "request is not cancellable".to_owned(),
        }
    }
}

/// Separate, root-only recovery control plane. It is deliberately not part of
/// the greeter request protocol.
pub trait RecoveryAdminHandler: Send + Sync {
    fn handle_recovery_admin(
        &self,
        request: niralis_session::RecoveryAdminRequest,
    ) -> std::result::Result<niralis_session::RecoveryAdminResponse, String>;
}

pub struct DaemonHandler<L, U, D> {
    config: Config,
    login_backend: L,
    user_directory: U,
    session_directory: D,
    rate_limiter: std::sync::Mutex<LoginRateLimiter>,
    transactions: transactions::TransactionTable,
}

impl<L, U, D> DaemonHandler<L, U, D>
where
    L: LoginBackend,
    U: UserDirectory,
    D: SessionDirectory,
{
    pub fn new(config: Config, login_backend: L, user_directory: U, session_directory: D) -> Self {
        let rate_limiter = LoginRateLimiter::new(
            config.auth.max_attempts,
            Duration::from_secs(config.auth.cooldown_seconds),
        );

        Self {
            config,
            login_backend,
            user_directory,
            session_directory,
            rate_limiter: std::sync::Mutex::new(rate_limiter),
            transactions: transactions::TransactionTable::new(std::collections::HashMap::new()),
        }
    }
}

impl<L, U, D> RequestHandler for DaemonHandler<L, U, D>
where
    L: LoginBackend,
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
            } => {
                #[cfg(test)]
                {
                    self.handle_test_authenticated(NiralisRequest::Login {
                        username,
                        password,
                        session,
                    })
                }
                #[cfg(not(test))]
                {
                    let _ = (username, password, session);
                    NiralisResponse::Error {
                        message: "login requires an authenticated greeter connection".to_owned(),
                    }
                }
            }
            NiralisRequest::Shutdown | NiralisRequest::Reboot => NiralisResponse::Error {
                message: "not implemented in phase 1".to_owned(),
            },
        }
    }

    fn handle_authenticated(
        &self,
        authority: &crate::connection::GreeterConnectionAuthority,
        request_id: u64,
        request: NiralisRequest,
    ) -> NiralisResponse {
        match request {
            NiralisRequest::Login {
                username,
                password,
                session,
            } => {
                let binding = niralis_session::LoginRequestBinding {
                    connection_id: authority.connection_id().as_str().to_owned(),
                    connection_epoch: authority.connection_epoch(),
                    request_id,
                    seat: authority.seat().as_str().to_owned(),
                };
                transactions::begin(&self.transactions, &binding);
                let result = login::handle_login_with_binding(
                    self,
                    username,
                    password,
                    session,
                    Some(binding.clone()),
                );
                transactions::finish(
                    &self.transactions,
                    &binding,
                    matches!(result, NiralisResponse::LoginOk { .. }),
                );
                result
            }
            other => self.handle(other),
        }
    }

    fn connection_closed(&self, authority: &crate::connection::GreeterConnectionAuthority) {
        transactions::disconnect(self, &self.transactions, authority);
    }

    fn cancel_authenticated(
        &self,
        authority: &crate::connection::GreeterConnectionAuthority,
        _request_id: u64,
        target_request_id: u64,
    ) -> NiralisResponse {
        transactions::cancel(self, &self.transactions, authority, target_request_id)
    }
}

impl<L, U, D> DaemonHandler<L, U, D>
where
    L: LoginBackend,
    U: UserDirectory,
    D: SessionDirectory,
{
    #[cfg(test)]
    fn handle_test_authenticated(&self, request: NiralisRequest) -> NiralisResponse {
        let authority = crate::connection::GreeterConnectionAuthority::issue(
            niralis_protocol::GreeterConnectionId::new_for_wire("test-connection".to_owned()),
            1,
            niralis_protocol::SeatId::new_for_wire("seat0".to_owned()),
            crate::connection::ValidatedPeerIdentity {
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
                pid: None,
            },
        );
        self.handle_authenticated(&authority, 1, request)
    }
}

impl<L, U, D> RecoveryAdminHandler for DaemonHandler<L, U, D>
where
    L: LoginBackend,
    U: UserDirectory,
    D: SessionDirectory,
{
    fn handle_recovery_admin(
        &self,
        request: niralis_session::RecoveryAdminRequest,
    ) -> std::result::Result<niralis_session::RecoveryAdminResponse, String> {
        self.login_backend
            .recovery_admin(request)
            .map_err(|error| error.to_string())
    }
}

fn discovery_error_response(scope: &str, _error: DiscoveryError) -> NiralisResponse {
    NiralisResponse::Error {
        message: format!("failed to discover {scope}"),
    }
}
