
impl OwnedVirtualTerminal {
    fn allocate(seat: SeatId) -> Result<Self, VirtualTerminalError> {
        let control = open_device(c"/dev/console")?;
        let previous_number = KernelVtControl::new(control.as_raw_fd())
            .active()
            .map_err(|_| VirtualTerminalError::OperationFailed)?;
        let previous_vtnr =
            VirtualTerminalId::new(previous_number).ok_or(VirtualTerminalError::OperationFailed)?;
        let mut number: libc::c_int = 0;
        if unsafe { libc::ioctl(control.as_raw_fd(), VT_OPENQRY, &mut number) } < 0 {
            return Err(VirtualTerminalError::OpenQueryFailed(last_errno()));
        }
        let number = u32::try_from(number)
            .map_err(|_| VirtualTerminalError::InvalidAllocatedTerminal(number))?;
        if !(VT_MIN..=VT_MAX).contains(&number) {
            return Err(VirtualTerminalError::InvalidAllocatedTerminal(
                number as libc::c_int,
            ));
        }
        let device = format!("/dev/tty{number}");
        let device = std::ffi::CString::new(device)
            .map_err(|_| VirtualTerminalError::InvalidAllocatedTerminal(number as libc::c_int))?;
        let terminal = open_device(device.as_c_str())?;
        let stat = fstat(terminal.as_raw_fd())?;
        let major = libc::major(stat.st_rdev) as u32;
        let minor = libc::minor(stat.st_rdev) as u32;
        if major != 4 || minor != number {
            return Err(VirtualTerminalError::DeviceMismatch {
                expected: number,
                major,
                minor,
            });
        }
        let vtnr = VirtualTerminalId::new(number).ok_or(
            VirtualTerminalError::InvalidAllocatedTerminal(number as libc::c_int),
        )?;
        if vtnr == previous_vtnr {
            return Err(VirtualTerminalError::OperationFailed);
        }
        Ok(Self {
            seat,
            vtnr,
            previous_vtnr,
            control,
            terminal: OwnedTerminalHandleState::Held(terminal),
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
        let OwnedTerminalHandleState::Held(terminal) = &self.terminal else {
            return Err(VirtualTerminalError::OperationFailed);
        };
        let fd = unsafe { libc::fcntl(terminal.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
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
        if matches!(self.terminal, OwnedTerminalHandleState::Released) {
            return Ok(());
        }
        let control_fd = self.control.as_raw_fd();
        let result = if matches!(self.terminal, OwnedTerminalHandleState::Held(_)) {
            let mut operations = KernelVtReleaseOperations::new(control_fd, &mut self.terminal);
            release_allocated_terminal(
                &mut operations,
                self.vtnr.number(),
                self.previous_vtnr.number(),
                VT_RELEASE_WAIT,
            )
        } else {
            KernelVtControl::new(control_fd)
                .disallocate(self.vtnr.number())
                .map_err(|errno| VirtualTerminalError::CleanupOperationFailed {
                    stage: "disallocate",
                    errno,
                })
        };
        if result.is_ok() {
            self.terminal = OwnedTerminalHandleState::Released;
        }
        result
    }
}

trait VtControlOperations {
    fn active(&mut self) -> Result<u32, libc::c_int>;
    fn activate(&mut self, number: u32) -> Result<(), libc::c_int>;
    fn disallocate(&mut self, number: u32) -> Result<(), libc::c_int>;
}

trait VtReleaseOperations: VtControlOperations {
    fn close_terminal(&mut self);
}

struct KernelVtControl {
    fd: RawFd,
}

impl KernelVtControl {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl VtControlOperations for KernelVtControl {
    fn active(&mut self) -> Result<u32, libc::c_int> {
        let mut state = VtState {
            active: 0,
            signal: 0,
            state: 0,
        };
        if unsafe { libc::ioctl(self.fd, VT_GETSTATE, &mut state) } < 0 {
            Err(last_errno())
        } else {
            Ok(u32::from(state.active))
        }
    }

    fn activate(&mut self, number: u32) -> Result<(), libc::c_int> {
        if unsafe { libc::ioctl(self.fd, VT_ACTIVATE, number as libc::c_int) } < 0 {
            Err(last_errno())
        } else {
            Ok(())
        }
    }

    fn disallocate(&mut self, number: u32) -> Result<(), libc::c_int> {
        if unsafe { libc::ioctl(self.fd, VT_DISALLOCATE, number as libc::c_int) } < 0 {
            Err(last_errno())
        } else {
            Ok(())
        }
    }
}

struct KernelVtReleaseOperations<'a> {
    control: KernelVtControl,
    terminal: &'a mut OwnedTerminalHandleState,
}

impl<'a> KernelVtReleaseOperations<'a> {
    fn new(fd: RawFd, terminal: &'a mut OwnedTerminalHandleState) -> Self {
        Self {
            control: KernelVtControl::new(fd),
            terminal,
        }
    }
}

impl VtControlOperations for KernelVtReleaseOperations<'_> {
    fn active(&mut self) -> Result<u32, libc::c_int> {
        self.control.active()
    }

    fn activate(&mut self, number: u32) -> Result<(), libc::c_int> {
        self.control.activate(number)
    }

    fn disallocate(&mut self, number: u32) -> Result<(), libc::c_int> {
        self.control.disallocate(number)
    }
}

impl VtReleaseOperations for KernelVtReleaseOperations<'_> {
    fn close_terminal(&mut self) {
        self.terminal.close_terminal();
    }
}
