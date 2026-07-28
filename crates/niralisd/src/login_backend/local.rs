use niralis_auth::Authenticator;
use niralis_session::{
    LoginBackendFactory, SessionLauncher, StartedSession, UnauthenticatedLoginRequest,
    UnboundLoginBackend,
};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

use super::{map_session_error, LoginAttempt, LoginBackend, LoginBackendError};

pub struct LocalLoginBackendFactory {
    authenticator: Arc<dyn Authenticator>,
}

impl LocalLoginBackendFactory {
    pub fn new<A: Authenticator + 'static>(authenticator: A) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
        }
    }
}

impl LoginBackendFactory for LocalLoginBackendFactory {
    fn create_unbound(
        &self,
    ) -> Result<Box<dyn UnboundLoginBackend>, niralis_session::SessionError> {
        Ok(Box::new(UnboundLocalBackend {
            authenticator: Arc::clone(&self.authenticator),
        }))
    }
}

struct UnboundLocalBackend {
    authenticator: Arc<dyn Authenticator>,
}

impl UnboundLoginBackend for UnboundLocalBackend {
    fn authenticate(
        self: Box<Self>,
        request: &UnauthenticatedLoginRequest,
        secret: niralis_session::LoginSecret,
    ) -> Result<String, niralis_session::SessionError> {
        let secret = secret.consume();
        let transaction = self
            .authenticator
            .authenticate(&request.username, &secret)
            .map_err(|_| niralis_session::SessionError::AuthenticationFailed)?;
        Ok(transaction.user().username.clone())
    }
}

pub struct LocalLoginBackend<A, S> {
    factory: LocalLoginBackendFactory,
    session_launcher: S,
    _marker: std::marker::PhantomData<fn() -> A>,
}

impl<A: Authenticator + 'static, S> LocalLoginBackend<A, S> {
    pub fn new(authenticator: A, session_launcher: S) -> Self {
        Self {
            factory: LocalLoginBackendFactory::new(authenticator),
            session_launcher,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<A, S> LoginBackend for LocalLoginBackend<A, S>
where
    A: Authenticator,
    S: SessionLauncher,
{
    fn login(&self, attempt: LoginAttempt) -> Result<StartedSession, LoginBackendError> {
        let request = UnauthenticatedLoginRequest {
            username: attempt.username,
            session: attempt.session,
            attempt_id: attempt.attempt_id,
            launch_plan: Some(niralis_session::SessionExecPlan {
                source_path: attempt
                    .launch_spec
                    .source_path
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
                executable: attempt
                    .launch_spec
                    .executable
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
                argv: attempt
                    .launch_spec
                    .argv
                    .iter()
                    .map(|arg| arg.as_bytes().to_vec())
                    .collect(),
            }),
            pam_service: None,
            connection: attempt.connection,
        };
        self.session_launcher
            .begin_login(
                request,
                niralis_session::LoginSecret::new(attempt.password.to_string()),
                &self.factory,
            )
            .map_err(map_session_error)
    }
}
