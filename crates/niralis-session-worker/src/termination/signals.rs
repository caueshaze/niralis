const SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

pub struct WorkerSignalFd {
    fd: OwnedFd,
    previous_mask: libc::sigset_t,
}

impl WorkerSignalFd {
    pub fn install() -> io::Result<Self> {
        let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigemptyset(&mut mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for signal in SIGNALS {
            if unsafe { libc::sigaddset(&mut mask, signal) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut previous_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mask_result =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous_mask) };
        if mask_result != 0 {
            return Err(io::Error::from_raw_os_error(mask_result));
        }
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if fd < 0 {
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut())
            };
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            previous_mask,
        })
    }

    pub fn read_signal(&self) -> io::Result<Option<libc::c_int>> {
        let mut info = unsafe { std::mem::zeroed::<libc::signalfd_siginfo>() };
        let read = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&mut info as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of::<libc::signalfd_siginfo>(),
            )
        };
        if read == std::mem::size_of::<libc::signalfd_siginfo>() as isize {
            let signal = info.ssi_signo as libc::c_int;
            return SIGNALS
                .contains(&signal)
                .then_some(signal)
                .map(Some)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "unexpected signalfd signal")
                });
        }
        let error = io::Error::last_os_error();
        if read < 0 && error.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error)
        }
    }
}

impl AsRawFd for WorkerSignalFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
impl Drop for WorkerSignalFd {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut())
        };
    }
}

pub fn restore_payload_signal_state() -> io::Result<()> {
    let mut empty = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigemptyset(&mut empty) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mask_result =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) };
    if mask_result != 0 {
        return Err(io::Error::from_raw_os_error(mask_result));
    }
    for signal in SIGNALS {
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = libc::SIG_DFL;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub struct GraceTimerFd(OwnedFd);
impl GraceTimerFd {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
        }
    }
    pub fn arm_once(&self, duration: Duration) -> io::Result<()> {
        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: duration.as_secs().try_into().unwrap_or(libc::time_t::MAX),
                tv_nsec: duration.subsec_nanos().into(),
            },
        };
        if unsafe { libc::timerfd_settime(self.0.as_raw_fd(), 0, &spec, std::ptr::null_mut()) } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    pub fn consume(&self) -> io::Result<bool> {
        let mut expirations = 0_u64;
        let read = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                (&mut expirations as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if read == std::mem::size_of::<u64>() as isize {
            Ok(expirations > 0)
        } else {
            let error = io::Error::last_os_error();
            if read < 0 && error.kind() == io::ErrorKind::WouldBlock {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}
impl AsRawFd for GraceTimerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub fn read_signal_fd(fd: RawFd) -> io::Result<Option<libc::c_int>> {
    let mut info = unsafe { std::mem::zeroed::<libc::signalfd_siginfo>() };
    let read = unsafe {
        libc::read(
            fd,
            (&mut info as *mut libc::signalfd_siginfo).cast(),
            std::mem::size_of::<libc::signalfd_siginfo>(),
        )
    };
    if read == std::mem::size_of::<libc::signalfd_siginfo>() as isize {
        let signal = info.ssi_signo as libc::c_int;
        return SIGNALS
            .contains(&signal)
            .then_some(signal)
            .map(Some)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unexpected signalfd signal")
            });
    }
    let error = io::Error::last_os_error();
    if read < 0 && error.kind() == io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(error)
    }
}
