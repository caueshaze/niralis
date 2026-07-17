use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use libloading::{Library, Symbol};
use niralis_auth::{SeatId, VirtualTerminalId};

const VT_OPENQRY: libc::c_ulong = 0x5600;
const VT_ACTIVATE: libc::c_ulong = 0x5606;
const VT_GETSTATE: libc::c_ulong = 0x5603;
const VT_DISALLOCATE: libc::c_ulong = 0x5608;
const VT_MIN: u32 = 1;
const VT_MAX: u32 = 63;
const VT_RELEASE_WAIT: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum VirtualTerminalError {
    #[error("seat does not support virtual terminals")]
    UnsupportedSeat,
    #[error("libsystemd is unavailable")]
    LibraryUnavailable,
    #[error("libsystemd does not export sd_seat_can_graphical")]
    SymbolUnavailable,
    #[error("seat name contains a NUL byte")]
    InvalidSeatName,
    #[error("seat is not graphical")]
    SeatNotGraphical,
    #[error("could not query whether seat is graphical: {0}")]
    SeatQueryFailed(libc::c_int),
    #[error("could not open virtual terminal device {path} (errno {errno})")]
    DeviceOpenFailed { path: String, errno: libc::c_int },
    #[error("VT_OPENQRY failed (errno {0})")]
    OpenQueryFailed(libc::c_int),
    #[error("VT_OPENQRY returned invalid terminal number {0}")]
    InvalidAllocatedTerminal(libc::c_int),
    #[error("virtual terminal device metadata query failed (errno {0})")]
    DeviceMetadataFailed(libc::c_int),
    #[error("allocated terminal device does not match tty{expected}: major={major} minor={minor}")]
    DeviceMismatch {
        expected: u32,
        major: u32,
        minor: u32,
    },
    #[error("virtual terminal operation failed")]
    OperationFailed,
    #[error("virtual terminal cleanup failed")]
    CleanupFailed,
    #[error("virtual terminal cleanup failed during {stage} (errno {errno})")]
    CleanupOperationFailed {
        stage: &'static str,
        errno: libc::c_int,
    },
    #[error("virtual terminal cleanup timed out while restoring the previous terminal")]
    CleanupTimedOut,
}

pub trait VirtualTerminalLease: Send {
    fn seat(&self) -> &SeatId;
    fn vtnr(&self) -> VirtualTerminalId;
    fn duplicate_terminal_fd(&self) -> Result<OwnedFd, VirtualTerminalError>;
    fn activate(&mut self, wait: Duration) -> Result<(), VirtualTerminalError>;
    fn release(&mut self) -> Result<(), VirtualTerminalError>;
}

pub trait VirtualTerminalAllocator: Send + Sync {
    fn allocate(
        &self,
        seat: &SeatId,
    ) -> Result<Box<dyn VirtualTerminalLease>, VirtualTerminalError>;
}

pub struct VirtualTerminalGuard {
    lease: Option<Box<dyn VirtualTerminalLease>>,
    release_result: Option<Result<(), VirtualTerminalError>>,
}

impl VirtualTerminalGuard {
    pub fn new(lease: Box<dyn VirtualTerminalLease>) -> Self {
        Self {
            lease: Some(lease),
            release_result: None,
        }
    }

    pub fn lease(&self) -> &dyn VirtualTerminalLease {
        self.lease.as_deref().expect("VT lease present")
    }

    pub fn lease_mut(&mut self) -> &mut dyn VirtualTerminalLease {
        self.lease.as_deref_mut().expect("VT lease present")
    }

    pub fn release(&mut self) -> Result<(), VirtualTerminalError> {
        if let Some(result) = &self.release_result {
            return result.clone();
        }
        let result = if let Some(lease) = self.lease.as_deref_mut() {
            lease.release()
        } else {
            Ok(())
        };
        self.release_result = Some(result.clone());
        result
    }
}

impl Drop for VirtualTerminalGuard {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxVirtualTerminalAllocator;

impl VirtualTerminalAllocator for LinuxVirtualTerminalAllocator {
    fn allocate(
        &self,
        seat: &SeatId,
    ) -> Result<Box<dyn VirtualTerminalLease>, VirtualTerminalError> {
        if seat.as_str() != "seat0" {
            return Err(VirtualTerminalError::UnsupportedSeat);
        }
        let library = unsafe {
            Library::new("libsystemd.so.0").map_err(|_| VirtualTerminalError::LibraryUnavailable)?
        };
        let can_graphical: Symbol<unsafe extern "C" fn(*const libc::c_char) -> libc::c_int> =
            unsafe { library.get(b"sd_seat_can_graphical\0") }
                .map_err(|_| VirtualTerminalError::SymbolUnavailable)?;
        ensure_graphical_seat(seat.as_str(), |seat_name| {
            // SAFETY: `seat_name` is NUL-terminated and remains valid during the call.
            Ok(unsafe { can_graphical(seat_name.as_ptr()) })
        })?;
        Ok(Box::new(OwnedVirtualTerminal::allocate(seat.clone())?))
    }
}

fn ensure_graphical_seat<F>(seat: &str, query: F) -> Result<(), VirtualTerminalError>
where
    F: FnOnce(&CStr) -> Result<libc::c_int, VirtualTerminalError>,
{
    let seat_name =
        std::ffi::CString::new(seat).map_err(|_| VirtualTerminalError::InvalidSeatName)?;
    match query(seat_name.as_c_str())? {
        result if result > 0 => Ok(()),
        0 => Err(VirtualTerminalError::SeatNotGraphical),
        result => Err(VirtualTerminalError::SeatQueryFailed(result)),
    }
}

pub struct OwnedVirtualTerminal {
    seat: SeatId,
    vtnr: VirtualTerminalId,
    previous_vtnr: VirtualTerminalId,
    control: OwnedFd,
    terminal: OwnedTerminalHandleState,
}

enum OwnedTerminalHandleState {
    Held(OwnedFd),
    TerminalClosed,
    Released,
}

impl OwnedTerminalHandleState {
    fn close_terminal(&mut self) {
        if matches!(self, Self::Held(_)) {
            *self = Self::TerminalClosed;
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Held(_) => "held",
            Self::TerminalClosed => "terminal_closed",
            Self::Released => "released",
        }
    }
}

impl std::fmt::Debug for OwnedVirtualTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedVirtualTerminal")
            .field("seat", &self.seat.as_str())
            .field("vtnr", &self.vtnr.number())
            .field("state", &self.terminal.label())
            .finish()
    }
}
