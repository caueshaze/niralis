use std::ffi::{CStr, CString};

use pam::Conversation;
use tracing::trace;
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct SilentPasswordConversation {
    username: String,
    password: Zeroizing<String>,
}

impl SilentPasswordConversation {
    pub(crate) fn new() -> Self {
        Self::default()
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
    fn prompt_echo(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.username.clone()).map_err(|_| ())
    }

    fn prompt_blind(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.password.as_str()).map_err(|_| ())
    }

    fn info(&mut self, _msg: &CStr) {
        trace!("PAM sent an informational conversation message");
    }

    fn error(&mut self, _msg: &CStr) {
        trace!("PAM sent an error conversation message");
    }
}
