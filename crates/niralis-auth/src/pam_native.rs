use std::ffi::{CStr, CString};
use std::ptr::NonNull;

use pam::{Conversation, PamFlag, PamItemType, PamReturnCode};

use crate::conversation::SilentPasswordConversation;
use crate::{AuthSessionError, AuthenticatedUser, PamSessionMetadata};

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
        let authenticated = pam::authenticate(transaction.handle_mut(), PamFlag::None)
            == PamReturnCode::Success
            && pam::acct_mgmt(transaction.handle_mut(), PamFlag::None) == PamReturnCode::Success;
        transaction.conversation.clear_password();
        if !authenticated {
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
        for entry in metadata.entries() {
            CString::new(entry.as_str()).map_err(|_| AuthSessionError::OpenFailed)?;
            pam::putenv(self.handle_mut(), &entry).map_err(|_| AuthSessionError::OpenFailed)?;
        }
        if pam::setcred(self.handle_mut(), PamFlag::Establish_Cred) != PamReturnCode::Success {
            return Err(AuthSessionError::OpenFailed);
        }
        self.credentials_established = true;
        if pam::open_session(self.handle_mut(), false) != PamReturnCode::Success {
            self.cleanup();
            return Err(AuthSessionError::OpenFailed);
        }
        self.session_open = true;
        if pam::setcred(self.handle_mut(), PamFlag::Reinitialize_Cred) != PamReturnCode::Success {
            self.cleanup();
            return Err(AuthSessionError::OpenFailed);
        }
        Ok(())
    }

    pub(crate) fn password_is_cleared(&self) -> bool {
        self.conversation.password_is_cleared()
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
        let answer = match (*message).msg_style {
            1 => conversation.prompt_echo(text),
            2 => conversation.prompt_blind(text),
            3 => {
                conversation.info(text);
                continue;
            }
            4 => {
                conversation.error(text);
                continue;
            }
            _ => Err(()),
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
