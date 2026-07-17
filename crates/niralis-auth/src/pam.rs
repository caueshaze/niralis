use tracing::debug;

use crate::pam_native::NativePamTransaction;
use crate::{
    AuthError, AuthSessionError, AuthenticatedTransaction, AuthenticatedUser, Authenticator,
};

#[derive(Debug, Clone)]
pub struct PamAuthenticator {
    service: String,
}

impl PamAuthenticator {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }
}

impl Authenticator for PamAuthenticator {
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn AuthenticatedTransaction>, AuthError> {
        let (transaction, user) = NativePamTransaction::authenticate(
            &self.service,
            username.to_owned(),
            password.to_owned(),
        )
        .map_err(|_| AuthError::LoginFailed)?;

        Ok(Box::new(PamAuthenticatedTransaction { user, transaction }))
    }
}

pub(crate) struct PamAuthenticatedTransaction {
    user: AuthenticatedUser,
    transaction: NativePamTransaction,
}

impl AuthenticatedTransaction for PamAuthenticatedTransaction {
    fn user(&self) -> &AuthenticatedUser {
        &self.user
    }

    fn open_session(
        &mut self,
        metadata: &crate::PamSessionMetadata,
    ) -> Result<(), AuthSessionError> {
        self.transaction.open_session(metadata).map_err(|_| {
            debug!(username = %self.user.username, "PAM open_session failed");
            AuthSessionError::OpenFailed
        })
    }

    fn session_environment(&mut self) -> Result<crate::PamSessionEnvironment, AuthSessionError> {
        self.transaction.session_environment()
    }

    fn close_session(&mut self) -> Result<(), AuthSessionError> {
        self.transaction.close_session()
    }
}

impl std::fmt::Debug for PamAuthenticatedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PamAuthenticatedTransaction")
            .field("username", &self.user.username)
            .field("transaction", &"[redacted]")
            .finish()
    }
}

impl PamAuthenticatedTransaction {
    #[allow(dead_code)]
    pub(crate) fn password_is_cleared(&self) -> bool {
        self.transaction.password_is_cleared()
    }
}
