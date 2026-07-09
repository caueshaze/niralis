use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use niralis_auth::Authenticator;
use niralis_protocol::{DaemonStatus, NiralisRequest, NiralisResponse, SessionInfo, UserInfo};
use niralis_session::{SessionLauncher, SessionRequest};
use tracing::{debug, info};

use crate::config::Config;

pub trait RequestHandler: Send + Sync {
    fn handle(&self, request: NiralisRequest) -> NiralisResponse;
}

#[derive(Debug)]
pub struct DaemonHandler<A, S> {
    config: Config,
    authenticator: A,
    session_launcher: S,
    rate_limiter: Mutex<LoginRateLimiter>,
}

impl<A, S> DaemonHandler<A, S> {
    pub fn new(config: Config, authenticator: A, session_launcher: S) -> Self {
        let rate_limiter = LoginRateLimiter::new(
            config.auth.max_attempts,
            Duration::from_secs(config.auth.cooldown_seconds),
        );

        Self {
            config,
            authenticator,
            session_launcher,
            rate_limiter: Mutex::new(rate_limiter),
        }
    }
}

impl<A, S> RequestHandler for DaemonHandler<A, S>
where
    A: Authenticator,
    S: SessionLauncher,
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
            NiralisRequest::GetUsers => match self.authenticator.users() {
                Ok(users) => NiralisResponse::Users {
                    users: users
                        .into_iter()
                        .map(|user| UserInfo {
                            username: user.username,
                            display_name: user.display_name,
                        })
                        .collect(),
                },
                Err(_) => NiralisResponse::Error {
                    message: "failed to load users".to_owned(),
                },
            },
            NiralisRequest::Login {
                username,
                password,
                session,
            } => self.handle_login(username, password, session),
            NiralisRequest::Shutdown | NiralisRequest::Reboot => NiralisResponse::Error {
                message: "not implemented in phase 1".to_owned(),
            },
        }
    }
}

impl<A, S> DaemonHandler<A, S>
where
    A: Authenticator,
    S: SessionLauncher,
{
    fn handle_login(&self, username: String, password: String, session: String) -> NiralisResponse {
        if self.is_rate_limited(&username) {
            info!(username = %username, "login rejected by rate limit");
            return login_failed();
        }

        match self.authenticator.authenticate(&username, &password) {
            Ok(user) => {
                self.reset_rate_limit(&username);

                let request = SessionRequest {
                    username: user.username,
                    session,
                };

                match self.session_launcher.start_session(request) {
                    Ok(started) => NiralisResponse::LoginOk {
                        session: SessionInfo {
                            username: started.username,
                            session: started.session,
                        },
                    },
                    Err(_) => NiralisResponse::Error {
                        message: "failed to start session".to_owned(),
                    },
                }
            }
            Err(_) => {
                self.record_login_failure(&username);
                login_failed()
            }
        }
    }

    fn is_rate_limited(&self, username: &str) -> bool {
        match self.rate_limiter.lock() {
            Ok(mut limiter) => limiter.is_limited(username, Instant::now()),
            Err(_) => {
                debug!("login rate limiter mutex is poisoned");
                true
            }
        }
    }

    fn record_login_failure(&self, username: &str) {
        match self.rate_limiter.lock() {
            Ok(mut limiter) => limiter.record_failure(username, Instant::now()),
            Err(_) => debug!("login rate limiter mutex is poisoned"),
        }
    }

    fn reset_rate_limit(&self, username: &str) {
        match self.rate_limiter.lock() {
            Ok(mut limiter) => limiter.reset(username),
            Err(_) => debug!("login rate limiter mutex is poisoned"),
        }
    }
}

fn login_failed() -> NiralisResponse {
    NiralisResponse::LoginFailed {
        message: "login failed".to_owned(),
    }
}

#[derive(Debug)]
struct LoginRateLimiter {
    max_attempts: u32,
    cooldown: Duration,
    failures: HashMap<String, LoginFailureState>,
}

#[derive(Debug, Clone, Copy)]
struct LoginFailureState {
    attempts: u32,
    last_failure: Instant,
}

impl LoginRateLimiter {
    fn new(max_attempts: u32, cooldown: Duration) -> Self {
        Self {
            max_attempts,
            cooldown,
            failures: HashMap::new(),
        }
    }

    fn is_limited(&mut self, username: &str, now: Instant) -> bool {
        if self.max_attempts == 0 {
            return false;
        }

        let Some(state) = self.failures.get(username).copied() else {
            return false;
        };

        if state.attempts < self.max_attempts {
            return false;
        }

        if now.duration_since(state.last_failure) >= self.cooldown {
            self.failures.remove(username);
            false
        } else {
            true
        }
    }

    fn record_failure(&mut self, username: &str, now: Instant) {
        if self.max_attempts == 0 {
            return;
        }

        self.failures
            .entry(username.to_owned())
            .and_modify(|state| {
                state.attempts = state.attempts.saturating_add(1);
                state.last_failure = now;
            })
            .or_insert(LoginFailureState {
                attempts: 1,
                last_failure: now,
            });
    }

    fn reset(&mut self, username: &str) {
        self.failures.remove(username);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use niralis_auth::{AuthError, AuthenticatedUser, MockAuthenticator};
    use niralis_session::MockSessionLauncher;

    use super::*;

    fn handler() -> DaemonHandler<MockAuthenticator, MockSessionLauncher> {
        DaemonHandler::new(Config::default(), MockAuthenticator, MockSessionLauncher)
    }

    fn test_config(max_attempts: u32, cooldown_seconds: u64) -> Config {
        let mut config = Config::default();
        config.auth.max_attempts = max_attempts;
        config.auth.cooldown_seconds = cooldown_seconds;
        config
    }

    #[test]
    fn handles_status() {
        let response = handler().handle(NiralisRequest::Status);

        match response {
            NiralisResponse::Status { status } => {
                assert_eq!(status.default_session, "niri");
            }
            other => panic!("expected status response, got {other:?}"),
        }
    }

    #[test]
    fn handles_get_users() {
        let response = handler().handle(NiralisRequest::GetUsers);

        assert_eq!(
            response,
            NiralisResponse::Users {
                users: vec![UserInfo {
                    username: "test".to_owned(),
                    display_name: "Test User".to_owned(),
                }]
            }
        );
    }

    #[test]
    fn handles_valid_login() {
        let response = handler().handle(NiralisRequest::Login {
            username: "test".to_owned(),
            password: "test".to_owned(),
            session: "niri".to_owned(),
        });

        assert_eq!(
            response,
            NiralisResponse::LoginOk {
                session: SessionInfo {
                    username: "test".to_owned(),
                    session: "niri".to_owned(),
                }
            }
        );
    }

    #[test]
    fn handles_invalid_login_with_generic_failure() {
        let response = handler().handle(NiralisRequest::Login {
            username: "test".to_owned(),
            password: "wrong-password".to_owned(),
            session: "niri".to_owned(),
        });

        assert_eq!(response, login_failed());
    }

    #[test]
    fn successive_failures_activate_rate_limit_before_authenticator() {
        let auth = CountingAuthenticator::always_fails();
        let calls = auth.calls.clone();
        let handler = DaemonHandler::new(test_config(2, 60), auth, MockSessionLauncher);

        for _ in 0..3 {
            assert_eq!(
                handler.handle(NiralisRequest::Login {
                    username: "blocked".to_owned(),
                    password: "bad".to_owned(),
                    session: "niri".to_owned(),
                }),
                login_failed()
            );
        }

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn success_resets_rate_limit() {
        let auth = CountingAuthenticator::fails_then_succeeds(1);
        let calls = auth.calls.clone();
        let handler = DaemonHandler::new(test_config(2, 60), auth, MockSessionLauncher);

        assert_eq!(
            handler.handle(NiralisRequest::Login {
                username: "test".to_owned(),
                password: "bad".to_owned(),
                session: "niri".to_owned(),
            }),
            login_failed()
        );

        assert!(matches!(
            handler.handle(NiralisRequest::Login {
                username: "test".to_owned(),
                password: "test".to_owned(),
                session: "niri".to_owned(),
            }),
            NiralisResponse::LoginOk { .. }
        ));

        assert!(matches!(
            handler.handle(NiralisRequest::Login {
                username: "test".to_owned(),
                password: "test".to_owned(),
                session: "niri".to_owned(),
            }),
            NiralisResponse::LoginOk { .. }
        ));

        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn rate_limit_response_is_generic() {
        let auth = CountingAuthenticator::always_fails();
        let handler = DaemonHandler::new(test_config(1, 60), auth, MockSessionLauncher);

        assert_eq!(
            handler.handle(NiralisRequest::Login {
                username: "test".to_owned(),
                password: "bad".to_owned(),
                session: "niri".to_owned(),
            }),
            login_failed()
        );

        assert_eq!(
            handler.handle(NiralisRequest::Login {
                username: "test".to_owned(),
                password: "bad".to_owned(),
                session: "niri".to_owned(),
            }),
            login_failed()
        );
    }

    #[test]
    fn shutdown_is_not_implemented() {
        let response = handler().handle(NiralisRequest::Shutdown);

        assert_eq!(
            response,
            NiralisResponse::Error {
                message: "not implemented in phase 1".to_owned(),
            }
        );
    }

    #[test]
    fn reboot_is_not_implemented() {
        let response = handler().handle(NiralisRequest::Reboot);

        assert_eq!(
            response,
            NiralisResponse::Error {
                message: "not implemented in phase 1".to_owned(),
            }
        );
    }

    struct CountingAuthenticator {
        calls: std::sync::Arc<AtomicUsize>,
        failures_before_success: Option<usize>,
    }

    impl CountingAuthenticator {
        fn always_fails() -> Self {
            Self {
                calls: std::sync::Arc::new(AtomicUsize::new(0)),
                failures_before_success: None,
            }
        }

        fn fails_then_succeeds(failures_before_success: usize) -> Self {
            Self {
                calls: std::sync::Arc::new(AtomicUsize::new(0)),
                failures_before_success: Some(failures_before_success),
            }
        }
    }

    impl Authenticator for CountingAuthenticator {
        fn authenticate(
            &self,
            username: &str,
            _password: &str,
        ) -> Result<AuthenticatedUser, AuthError> {
            let previous_calls = self.calls.fetch_add(1, Ordering::SeqCst);

            match self.failures_before_success {
                Some(limit) if previous_calls >= limit => Ok(AuthenticatedUser {
                    username: username.to_owned(),
                    display_name: username.to_owned(),
                }),
                _ => Err(AuthError::LoginFailed),
            }
        }

        fn users(&self) -> Result<Vec<AuthenticatedUser>, AuthError> {
            Ok(Vec::new())
        }
    }
}
