use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use niralis_auth::{
    AuthError, AuthSessionError, AuthenticatedTransaction, AuthenticatedUser, Authenticator,
};

pub(crate) struct CountingAuthenticator {
    pub(crate) calls: Arc<AtomicUsize>,
    failures_before_success: Option<usize>,
}

impl CountingAuthenticator {
    pub(crate) fn always_fails() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            failures_before_success: None,
        }
    }

    pub(crate) fn fails_then_succeeds(failures_before_success: usize) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            failures_before_success: Some(failures_before_success),
        }
    }
}

impl Authenticator for CountingAuthenticator {
    fn authenticate(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError> {
        let previous_calls = self.calls.fetch_add(1, Ordering::SeqCst);
        match self.failures_before_success {
            Some(limit) if previous_calls >= limit => {
                Ok(Box::new(StaticTransaction::new(username.to_owned())))
            }
            _ => Err(AuthError::LoginFailed),
        }
    }
}

struct StaticTransaction {
    user: AuthenticatedUser,
}

impl StaticTransaction {
    fn new(username: String) -> Self {
        Self {
            user: AuthenticatedUser {
                display_name: username.clone(),
                username,
            },
        }
    }
}

impl AuthenticatedTransaction for StaticTransaction {
    fn user(&self) -> &AuthenticatedUser {
        &self.user
    }

    fn open_session(&mut self) -> Result<(), AuthSessionError> {
        Ok(())
    }
}
