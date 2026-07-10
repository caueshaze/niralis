use std::ffi::{CStr, CString};
use std::ptr::NonNull;

use pam::{Conversation, PamFlag, PamItemType, PamReturnCode};
use tracing::debug;

use crate::conversation::SilentPasswordConversation;
use crate::{
    AuthSessionError, AuthenticatedUser, PamSessionEnvironment, PamSessionMetadata, PamUnixPath,
};

pub(crate) struct NativePamTransaction {
    handle: NonNull<pam::PamHandle>,
    conversation: Box<SilentPasswordConversation>,
    credentials_established: bool,
    session_open: bool,
    ended: bool,
}

// The transaction is created, used, and dropped only by the dedicated worker.
// libpam handles are not shared; `Send` preserves the existing trait boundary.
unsafe impl Send for NativePamTransaction {}

impl NativePamTransaction {
    pub(crate) fn authenticate(
        service: &str,
        username: String,
        password: String,
    ) -> Result<(Self, AuthenticatedUser), ()> {
        let mut conversation = Box::new(SilentPasswordConversation::new());
        conversation.set_credentials(username, password);
        let callback = pam::ffi::pam_conv {
            conv: Some(converse),
            appdata_ptr: (&mut *conversation as *mut SilentPasswordConversation).cast(),
        };
        let handle = pam::start(service, None, &callback).map_err(|_| ())?;
        let mut transaction = Self {
            handle: NonNull::from(handle),
            conversation,
            credentials_established: false,
            session_open: false,
            ended: false,
        };
        let authenticate_result = pam::authenticate(transaction.handle_mut(), PamFlag::None);
        transaction.conversation.clear_password();
        if authenticate_result != PamReturnCode::Success {
            debug!(stage = "pam_authenticate", result = ?authenticate_result, "PAM authentication failed");
            transaction.cleanup();
            return Err(());
        }
        let account_result = pam::acct_mgmt(transaction.handle_mut(), PamFlag::None);
        if account_result != PamReturnCode::Success {
            debug!(stage = "pam_acct_mgmt", result = ?account_result, "PAM account validation failed");
            transaction.cleanup();
            return Err(());
        }
        let item = pam::get_item(transaction.handle_mut(), PamItemType::User).map_err(|_| ())?;
        let user_ptr: *const libc::c_char = unsafe { std::mem::transmute(item) };
        let username = unsafe { CStr::from_ptr(user_ptr) }
            .to_str()
            .map_err(|_| ())?
            .to_owned();
        Ok((
            transaction,
            AuthenticatedUser {
                username: username.clone(),
                display_name: username,
            },
        ))
    }

    pub(crate) fn open_session(
        &mut self,
        metadata: &PamSessionMetadata,
    ) -> Result<(), AuthSessionError> {
        if let Some(tty) = metadata.tty.as_deref() {
            let tty = CString::new(tty).map_err(|_| AuthSessionError::OpenFailed)?;
            let tty_item = unsafe { &*tty.as_ptr().cast::<libc::c_void>() };
            if let Err(error) = pam::set_item(self.handle_mut(), PamItemType::TTY, tty_item) {
                debug!(
                    stage = "pam_set_item(PAM_TTY)",
                    ?error,
                    "PAM terminal metadata setup failed"
                );
                return Err(AuthSessionError::OpenFailed);
            }
        }
        for entry in metadata.entries() {
            CString::new(entry.as_str()).map_err(|_| AuthSessionError::OpenFailed)?;
            pam::putenv(self.handle_mut(), &entry).map_err(|_| AuthSessionError::OpenFailed)?;
        }
        let setcred_result = pam::setcred(self.handle_mut(), PamFlag::Establish_Cred);
        if setcred_result != PamReturnCode::Success {
            debug!(stage = "pam_setcred_establish", result = ?setcred_result, "PAM credential setup failed");
            return Err(AuthSessionError::OpenFailed);
        }
        self.credentials_established = true;
        let open_result = pam::open_session(self.handle_mut(), false);
        if open_result != PamReturnCode::Success {
            debug!(stage = "pam_open_session", result = ?open_result, "PAM session open failed");
            self.cleanup();
            return Err(AuthSessionError::OpenFailed);
        }
        self.session_open = true;
        let reinitialize_result = pam::setcred(self.handle_mut(), PamFlag::Reinitialize_Cred);
        if reinitialize_result != PamReturnCode::Success {
            debug!(stage = "pam_setcred_reinitialize", result = ?reinitialize_result, "PAM credential reinitialization failed");
            self.cleanup();
            return Err(AuthSessionError::OpenFailed);
        }
        Ok(())
    }

    pub(crate) fn password_is_cleared(&self) -> bool {
        self.conversation.password_is_cleared()
    }

    pub(crate) fn session_environment(
        &mut self,
    ) -> Result<PamSessionEnvironment, AuthSessionError> {
        let session_id = self.pam_value("XDG_SESSION_ID").map_err(|error| {
            debug!(
                stage = "pam_getenv",
                key = "XDG_SESSION_ID",
                ?error,
                "required PAM session value unavailable"
            );
            error
        })?;
        if session_id.is_empty() || session_id.len() > 128 || session_id.as_bytes().contains(&0) {
            return Err(AuthSessionError::EnvironmentInvalid);
        }
        let runtime_dir =
            PamUnixPath::new(self.pam_value_bytes("XDG_RUNTIME_DIR").map_err(|error| {
                debug!(
                    stage = "pam_getenv",
                    key = "XDG_RUNTIME_DIR",
                    ?error,
                    "required PAM session value unavailable"
                );
                error
            })?)?;
        let imported_locale = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pam::getenvlist(self.handle_mut())
                .filter(|(key, _)| key == "LANG" || key == "LANGUAGE" || key.starts_with("LC_"))
                .take(256)
                .collect::<Vec<_>>()
        }))
        .map_err(|_| AuthSessionError::EnvironmentInvalid)?;
        let total = imported_locale
            .iter()
            .map(|(key, value)| key.len() + value.len() + 1)
            .sum::<usize>();
        if imported_locale
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 128 || value.len() > 16 * 1024)
            || total > 64 * 1024
        {
            return Err(AuthSessionError::EnvironmentInvalid);
        }
        Ok(PamSessionEnvironment {
            session_id,
            runtime_dir,
            imported_locale,
        })
    }

    fn pam_value(&mut self, name: &str) -> Result<String, AuthSessionError> {
        let bytes = self.pam_value_bytes(name)?;
        String::from_utf8(bytes).map_err(|_| AuthSessionError::EnvironmentInvalid)
    }

    fn pam_value_bytes(&mut self, name: &str) -> Result<Vec<u8>, AuthSessionError> {
        let name = CString::new(name).map_err(|_| AuthSessionError::EnvironmentInvalid)?;
        let value = unsafe { pam::ffi::pam_getenv(self.handle_mut(), name.as_ptr()) };
        if value.is_null() {
            return Err(AuthSessionError::EnvironmentInvalid);
        }
        let bytes = unsafe { CStr::from_ptr(value) }.to_bytes().to_vec();
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(AuthSessionError::EnvironmentInvalid);
        }
        Ok(bytes)
    }
    fn handle_mut(&mut self) -> &mut pam::PamHandle {
        unsafe { self.handle.as_mut() }
    }
    fn cleanup(&mut self) {
        if self.ended {
            return;
        }
        if self.session_open {
            let _ = pam::close_session(self.handle_mut(), false);
            self.session_open = false;
        }
        if self.credentials_established {
            let _ = pam::setcred(self.handle_mut(), PamFlag::Delete_Cred);
            self.credentials_established = false;
        }
        let _ = pam::end(self.handle_mut(), PamReturnCode::Success);
        self.ended = true;
    }
}
impl Drop for NativePamTransaction {
    fn drop(&mut self) {
        self.cleanup();
    }
}

unsafe extern "C" fn converse(
    count: libc::c_int,
    messages: *mut *const pam::ffi::pam_message,
    responses: *mut *mut pam::ffi::pam_response,
    data: *mut libc::c_void,
) -> libc::c_int {
    if count < 0 || messages.is_null() || responses.is_null() || data.is_null() {
        return PamReturnCode::Conv_Err as libc::c_int;
    }
    let output = libc::calloc(
        count as usize,
        std::mem::size_of::<pam::ffi::pam_response>(),
    )
    .cast::<pam::ffi::pam_response>();
    if output.is_null() {
        return PamReturnCode::Buf_Err as libc::c_int;
    }
    let conversation = &mut *data.cast::<SilentPasswordConversation>();
    for i in 0..count as isize {
        let message = *messages.offset(i);
        if message.is_null() || (*message).msg.is_null() {
            libc::free(output.cast());
            return PamReturnCode::Conv_Err as libc::c_int;
        }
        let text = CStr::from_ptr((*message).msg);
        let answer = match conversation_action((*message).msg_style) {
            ConversationAction::EchoOff => conversation.prompt_blind(text),
            ConversationAction::EchoOn => conversation.prompt_echo(text),
            ConversationAction::Error => {
                conversation.error(text);
                continue;
            }
            ConversationAction::Info => {
                conversation.info(text);
                continue;
            }
            ConversationAction::Invalid => Err(()),
        };
        let Ok(answer) = answer else {
            libc::free(output.cast());
            return PamReturnCode::Conv_Err as libc::c_int;
        };
        (*output.offset(i)).resp = libc::strdup(answer.as_ptr());
        if (*output.offset(i)).resp.is_null() {
            libc::free(output.cast());
            return PamReturnCode::Buf_Err as libc::c_int;
        }
    }
    *responses = output;
    PamReturnCode::Success as libc::c_int
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConversationAction {
    EchoOff,
    EchoOn,
    Error,
    Info,
    Invalid,
}

fn conversation_action(style: libc::c_int) -> ConversationAction {
    match style {
        1 => ConversationAction::EchoOff,
        2 => ConversationAction::EchoOn,
        3 => ConversationAction::Error,
        4 => ConversationAction::Info,
        _ => ConversationAction::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::{conversation_action, ConversationAction};

    #[test]
    fn maps_linux_pam_message_styles() {
        assert_eq!(conversation_action(1), ConversationAction::EchoOff);
        assert_eq!(conversation_action(2), ConversationAction::EchoOn);
        assert_eq!(conversation_action(3), ConversationAction::Error);
        assert_eq!(conversation_action(4), ConversationAction::Info);
        assert_eq!(conversation_action(0), ConversationAction::Invalid);
    }
}
