use pam::Client;
use tracing::debug;

use crate::conversation::SilentPasswordConversation;
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
        let mut client: Client<'static, SilentPasswordConversation> =
            Client::with_conversation(&self.service, SilentPasswordConversation::new()).map_err(
                |error| {
                    debug!(service = %self.service, ?error, "failed to initialize PAM client");
                    AuthError::InfrastructureFailed
                },
            )?;

        client
            .conversation_mut()
            .set_credentials(username.to_owned(), password.to_owned());

        let auth_result = client.authenticate();
        client.conversation_mut().clear_password();
        auth_result.map_err(|error| {
            debug!(service = %self.service, username = %username, ?error, "PAM authentication failed");
            AuthError::LoginFailed
        })?;

        let pam_username = client.get_user().map_err(|error| {
            debug!(
                service = %self.service,
                requested_username = %username,
                ?error,
                "failed to determine PAM authenticated username"
            );
            AuthError::AuthenticatedIdentityUnavailable
        })?;

        Ok(Box::new(PamAuthenticatedTransaction {
            user: authenticated_user_from_pam(pam_username),
            client,
        }))
    }
}

pub(crate) struct PamAuthenticatedTransaction {
    user: AuthenticatedUser,
    client: Client<'static, SilentPasswordConversation>,
}

impl AuthenticatedTransaction for PamAuthenticatedTransaction {
    fn user(&self) -> &AuthenticatedUser {
        &self.user
    }

    fn open_session(&mut self) -> Result<(), AuthSessionError> {
        self.client.open_session().map_err(|error| {
            debug!(username = %self.user.username, ?error, "PAM open_session failed");
            AuthSessionError::OpenFailed
        })
    }
}

impl std::fmt::Debug for PamAuthenticatedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PamAuthenticatedTransaction")
            .field("username", &self.user.username)
            .field("client", &"[redacted]")
            .finish()
    }
}

impl PamAuthenticatedTransaction {
    #[allow(dead_code)]
    pub(crate) fn password_is_cleared(&self) -> bool {
        self.client.conversation().password_is_cleared()
    }
}

pub(crate) fn authenticated_user_from_pam(pam_username: String) -> AuthenticatedUser {
    AuthenticatedUser {
        username: pam_username.clone(),
        display_name: pam_username,
    }
}
