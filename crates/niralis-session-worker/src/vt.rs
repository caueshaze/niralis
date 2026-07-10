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

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum VirtualTerminalError {
    #[error("seat does not support virtual terminals")]
    UnsupportedSeat,
    #[error("virtual terminal allocation failed")]
    AllocationFailed,
    #[error("virtual terminal operation failed")]
    OperationFailed,
    #[error("virtual terminal cleanup failed")]
    CleanupFailed,
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
    released: bool,
}

impl VirtualTerminalGuard {
    pub fn new(lease: Box<dyn VirtualTerminalLease>) -> Self {
        Self {
            lease: Some(lease),
            released: false,
        }
    }

    pub fn lease(&self) -> &dyn VirtualTerminalLease {
        self.lease.as_deref().expect("VT lease present")
    }

    pub fn lease_mut(&mut self) -> &mut dyn VirtualTerminalLease {
        self.lease.as_deref_mut().expect("VT lease present")
    }

    pub fn release(&mut self) -> Result<(), VirtualTerminalError> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        if let Some(lease) = self.lease.as_deref_mut() {
            lease.release()
        } else {
            Ok(())
        }
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
            Library::new("libsystemd.so.0").map_err(|_| VirtualTerminalError::UnsupportedSeat)?
        };
        let can_graphical: Symbol<unsafe extern "C" fn(*const libc::c_char) -> libc::c_int> =
            unsafe { library.get(b"sd_seat_can_graphical\0") }
                .map_err(|_| VirtualTerminalError::UnsupportedSeat)?;
        let seat_name = std::ffi::CString::new(seat.as_str())
            .map_err(|_| VirtualTerminalError::UnsupportedSeat)?;
        if unsafe { can_graphical(seat_name.as_ptr()) } <= 0 {
            return Err(VirtualTerminalError::UnsupportedSeat);
        }
        Ok(Box::new(OwnedVirtualTerminal::allocate(seat.clone())?))
    }
}

pub struct OwnedVirtualTerminal {
    seat: SeatId,
    vtnr: VirtualTerminalId,
    control: OwnedFd,
    terminal: OwnedFd,
    released: bool,
}

impl std::fmt::Debug for OwnedVirtualTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedVirtualTerminal")
            .field("seat", &self.seat.as_str())
            .field("vtnr", &self.vtnr.number())
            .field("released", &self.released)
            .finish()
    }
}

impl OwnedVirtualTerminal {
    fn allocate(seat: SeatId) -> Result<Self, VirtualTerminalError> {
        let control = open_device(c"/dev/console")?;
        let mut number: libc::c_int = 0;
        if unsafe { libc::ioctl(control.as_raw_fd(), VT_OPENQRY, &mut number) } < 0 {
            return Err(VirtualTerminalError::AllocationFailed);
        }
        let number = u32::try_from(number).map_err(|_| VirtualTerminalError::AllocationFailed)?;
        if !(VT_MIN..=VT_MAX).contains(&number) {
            return Err(VirtualTerminalError::AllocationFailed);
        }
        let device = format!("/dev/tty{number}");
        let device =
            std::ffi::CString::new(device).map_err(|_| VirtualTerminalError::AllocationFailed)?;
        let terminal = open_device(device.as_c_str())?;
        let stat = fstat(terminal.as_raw_fd())?;
        let major = libc::major(stat.st_rdev) as u32;
        let minor = libc::minor(stat.st_rdev) as u32;
        if major != 4 || minor != number {
            return Err(VirtualTerminalError::AllocationFailed);
        }
        let vtnr = VirtualTerminalId::new(number).ok_or(VirtualTerminalError::AllocationFailed)?;
        Ok(Self {
            seat,
            vtnr,
            control,
            terminal,
            released: false,
        })
    }
}

impl VirtualTerminalLease for OwnedVirtualTerminal {
    fn seat(&self) -> &SeatId {
        &self.seat
    }

    fn vtnr(&self) -> VirtualTerminalId {
        self.vtnr
    }

    fn duplicate_terminal_fd(&self) -> Result<OwnedFd, VirtualTerminalError> {
        let fd = unsafe { libc::fcntl(self.terminal.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(VirtualTerminalError::OperationFailed);
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn activate(&mut self, wait: Duration) -> Result<(), VirtualTerminalError> {
        let number = self.vtnr.number() as libc::c_int;
        if unsafe { libc::ioctl(self.control.as_raw_fd(), VT_ACTIVATE, number) } < 0 {
            return Err(VirtualTerminalError::OperationFailed);
        }
        if wait.is_zero() {
            return Ok(());
        }
        let deadline = Instant::now() + wait;
        loop {
            let mut state = VtState {
                active: 0,
                signal: 0,
                state: 0,
            };
            if unsafe { libc::ioctl(self.control.as_raw_fd(), VT_GETSTATE, &mut state) } < 0 {
                return Err(VirtualTerminalError::OperationFailed);
            }
            if u32::from(state.active) == self.vtnr.number() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(VirtualTerminalError::OperationFailed);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn release(&mut self) -> Result<(), VirtualTerminalError> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        let number = self.vtnr.number() as libc::c_int;
        if unsafe { libc::ioctl(self.control.as_raw_fd(), VT_DISALLOCATE, number) } < 0 {
            return Err(VirtualTerminalError::CleanupFailed);
        }
        Ok(())
    }
}

#[repr(C)]
struct VtState {
    active: libc::c_ushort,
    signal: libc::c_ushort,
    state: libc::c_ushort,
}

fn open_device(path: &CStr) -> Result<OwnedFd, VirtualTerminalError> {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(VirtualTerminalError::AllocationFailed);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: RawFd) -> Result<libc::stat, VirtualTerminalError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } < 0 {
        return Err(VirtualTerminalError::AllocationFailed);
    }
    Ok(stat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct FakeLease {
        seat: SeatId,
        vtnr: VirtualTerminalId,
        releases: Arc<AtomicUsize>,
    }

    impl VirtualTerminalLease for FakeLease {
        fn seat(&self) -> &SeatId {
            &self.seat
        }
        fn vtnr(&self) -> VirtualTerminalId {
            self.vtnr
        }
        fn duplicate_terminal_fd(&self) -> Result<OwnedFd, VirtualTerminalError> {
            Err(VirtualTerminalError::OperationFailed)
        }
        fn activate(&mut self, _wait: Duration) -> Result<(), VirtualTerminalError> {
            Ok(())
        }
        fn release(&mut self) -> Result<(), VirtualTerminalError> {
            self.releases.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn guard_release_is_idempotent_and_does_not_touch_real_vt() {
        let releases = Arc::new(AtomicUsize::new(0));
        let seat = SeatId::new("seat0".to_owned()).unwrap();
        let vtnr = VirtualTerminalId::new(2).unwrap();
        let mut guard = VirtualTerminalGuard::new(Box::new(FakeLease {
            seat,
            vtnr,
            releases: releases.clone(),
        }));
        guard.release().unwrap();
        guard.release().unwrap();
        assert_eq!(releases.load(Ordering::SeqCst), 1);
    }
}

#[cfg(all(test, feature = "dangerous-real-vt-smoke"))]
mod dangerous_real_vt_smoke {
    use super::*;

    #[test]
    #[ignore = "may open and disallocate a real VT; run only on a disposable test machine"]
    fn explicitly_enabled_real_vt_allocation_smoke() {
        assert_eq!(
            std::env::var("NIRALIS_ALLOW_REAL_VT_TEST").as_deref(),
            Ok("1"),
            "set NIRALIS_ALLOW_REAL_VT_TEST=1 explicitly"
        );
        let active = std::fs::read_to_string("/sys/class/tty/tty0/active").ok();
        let seat = SeatId::new("seat0".to_owned()).unwrap();
        let mut lease = LinuxVirtualTerminalAllocator
            .allocate(&seat)
            .expect("real VT allocation should succeed in the dedicated environment");
        let active_number = active
            .as_deref()
            .and_then(|value| value.strip_prefix("tty"))
            .and_then(|value| value.trim().parse::<u32>().ok());
        assert_ne!(Some(lease.vtnr().number()), active_number);
        lease
            .release()
            .expect("owned VT should be released by the smoke");
    }
}
