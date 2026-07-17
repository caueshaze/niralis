
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
