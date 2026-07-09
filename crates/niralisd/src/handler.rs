use niralis_auth::Authenticator;
use niralis_protocol::{DaemonStatus, NiralisRequest, NiralisResponse, SessionInfo, UserInfo};
use niralis_session::{SessionLauncher, SessionRequest};

use crate::config::Config;

pub trait RequestHandler: Send + Sync {
    fn handle(&self, request: NiralisRequest) -> NiralisResponse;
}

#[derive(Debug)]
pub struct DaemonHandler<A, S> {
    config: Config,
    authenticator: A,
    session_launcher: S,
}

impl<A, S> DaemonHandler<A, S> {
    pub fn new(config: Config, authenticator: A, session_launcher: S) -> Self {
        Self {
            config,
            authenticator,
            session_launcher,
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
            } => match self.authenticator.authenticate(&username, &password) {
                Ok(user) => {
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
                Err(_) => NiralisResponse::LoginFailed {
                    message: "login failed".to_owned(),
                },
            },
            NiralisRequest::Shutdown | NiralisRequest::Reboot => NiralisResponse::Error {
                message: "not implemented in phase 1".to_owned(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use niralis_auth::MockAuthenticator;
    use niralis_session::MockSessionLauncher;

    use super::*;

    fn handler() -> DaemonHandler<MockAuthenticator, MockSessionLauncher> {
        DaemonHandler::new(Config::default(), MockAuthenticator, MockSessionLauncher)
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

        assert_eq!(
            response,
            NiralisResponse::LoginFailed {
                message: "login failed".to_owned(),
            }
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
}
