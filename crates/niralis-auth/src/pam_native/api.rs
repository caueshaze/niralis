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
