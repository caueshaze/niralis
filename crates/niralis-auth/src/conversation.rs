use std::ffi::{CStr, CString};

use crate::PamConversationDriver;
use niralis_protocol::{PamMessageStyle, PamPromptResponse};
use pam::Conversation;
use tracing::trace;
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct SilentPasswordConversation {
    username: String,
    password: Zeroizing<String>,
    driver: Option<Box<dyn PamConversationDriver>>,
    failed: bool,
}

impl SilentPasswordConversation {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_driver(driver: Box<dyn PamConversationDriver>) -> Self {
        Self {
            driver: Some(driver),
            ..Self::default()
        }
    }

    pub(crate) fn set_credentials(&mut self, username: String, password: String) {
        self.username = username;
        self.password = Zeroizing::new(password);
    }

    pub(crate) fn clear_password(&mut self) {
        self.password = Zeroizing::new(String::new());
    }

    pub(crate) fn password_is_cleared(&self) -> bool {
        self.password.is_empty()
    }
}

impl Conversation for SilentPasswordConversation {
    fn prompt_echo(&mut self, msg: &CStr) -> Result<CString, ()> {
        if let Some(driver) = self.driver.as_mut() {
            return response_to_cstring(
                driver
                    .respond(PamMessageStyle::PromptEchoOn, msg)
                    .map_err(|_| ())?,
                false,
            );
        }
        CString::new(self.username.clone()).map_err(|_| ())
    }

    fn prompt_blind(&mut self, msg: &CStr) -> Result<CString, ()> {
        if let Some(driver) = self.driver.as_mut() {
            return response_to_cstring(
                driver
                    .respond(PamMessageStyle::PromptEchoOff, msg)
                    .map_err(|_| ())?,
                true,
            );
        }
        CString::new(self.password.as_str()).map_err(|_| ())
    }

    fn info(&mut self, _msg: &CStr) {
        if let Some(driver) = self.driver.as_mut() {
            if !matches!(
                driver.respond(PamMessageStyle::Informational, _msg),
                Ok(PamPromptResponse::None)
            ) {
                self.failed = true;
            }
        }
        trace!("PAM sent an informational conversation message");
    }

    fn error(&mut self, _msg: &CStr) {
        if let Some(driver) = self.driver.as_mut() {
            if !matches!(
                driver.respond(PamMessageStyle::Error, _msg),
                Ok(PamPromptResponse::None)
            ) {
                self.failed = true;
            }
        }
        trace!("PAM sent an error conversation message");
    }
}

impl SilentPasswordConversation {
    pub(crate) fn failed(&self) -> bool {
        self.failed
    }
}

fn response_to_cstring(response: PamPromptResponse, secret: bool) -> Result<CString, ()> {
    match (secret, response) {
        (true, PamPromptResponse::Secret(value)) => {
            CString::new(value.consume().to_string()).map_err(|_| ())
        }
        (false, PamPromptResponse::Text(value)) => CString::new(value).map_err(|_| ()),
        _ => Err(()),
    }
}
