use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Debug)]
pub(crate) struct OwnerWatch {
    destination: String,
    initial_owner: String,
    changed: Arc<AtomicBool>,
    event: OwnedFd,
    address: Option<String>,
}

impl OwnerWatch {
    #[cfg_attr(not(any(test, feature = "supervisor-test-fixtures")), allow(dead_code))]
    pub(crate) fn scripted() -> Self {
        let event = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        Self {
            destination: "test.owner".to_owned(),
            initial_owner: "test.owner".to_owned(),
            changed: Arc::new(AtomicBool::new(false)),
            event: unsafe { OwnedFd::from_raw_fd(event) },
            address: None,
        }
    }

    #[cfg_attr(not(any(test, feature = "supervisor-test-fixtures")), allow(dead_code))]
    pub(crate) fn invalidate_for_test(&self) {
        self.changed.store(true, Ordering::Release);
    }

    pub(crate) fn open(
        destination: &str,
        initial_owner: String,
    ) -> Result<Self, SupervisorRecoveryError> {
        Self::open_on_address(destination, initial_owner, None)
    }

    pub(crate) fn open_on_address(
        destination: &str,
        initial_owner: String,
        address: Option<String>,
    ) -> Result<Self, SupervisorRecoveryError> {
        let event = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if event < 0 {
            return Err(SupervisorRecoveryError::BusUnavailable);
        }
        let event = unsafe { OwnedFd::from_raw_fd(event) };
        let changed = Arc::new(AtomicBool::new(false));
        let thread_changed = Arc::clone(&changed);
        let name = destination.to_owned();
        let thread_address = address.clone();
        let thread_event = unsafe { libc::dup(event.as_raw_fd()) };
        if thread_event < 0 {
            return Err(SupervisorRecoveryError::BusUnavailable);
        }
        let thread_event = unsafe { OwnedFd::from_raw_fd(thread_event) };
        std::thread::Builder::new()
            .name("niralis-owner-watch".to_owned())
            .spawn(move || {
                let builder = match thread_address {
                    Some(address) => zbus::blocking::connection::Builder::address(address.as_str()),
                    None => zbus::blocking::connection::Builder::system(),
                };
                let Ok(connection) = builder.and_then(|builder| builder.build()) else {
                    return;
                };
                let Ok(proxy) = zbus::blocking::Proxy::new(
                    &connection,
                    DBUS_DESTINATION,
                    DBUS_PATH,
                    DBUS_INTERFACE,
                ) else {
                    return;
                };
                let Ok(mut signals) =
                    proxy.receive_signal_with_args("NameOwnerChanged", &[(0, name.as_str())])
                else {
                    return;
                };
                if signals.next().is_some() {
                    thread_changed.store(true, Ordering::Release);
                    let value = 1u64.to_ne_bytes();
                    let _ = unsafe {
                        libc::write(thread_event.as_raw_fd(), value.as_ptr().cast(), value.len())
                    };
                }
            })
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
        Ok(Self {
            destination: destination.to_owned(),
            initial_owner,
            changed,
            event,
            address,
        })
    }

    pub(crate) fn stable(&self) -> Result<(), SupervisorRecoveryError> {
        let mut descriptor = libc::pollfd {
            fd: self.event.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut descriptor, 1, 0) } > 0 {
            self.changed.store(true, Ordering::Release);
        }
        if self.changed.load(Ordering::Acquire) || self.current_owner()? != self.initial_owner {
            Err(SupervisorRecoveryError::BusUnavailable)
        } else {
            Ok(())
        }
    }

    fn current_owner(&self) -> Result<String, SupervisorRecoveryError> {
        let builder = match &self.address {
            Some(address) => zbus::blocking::connection::Builder::address(address.as_str()),
            None => zbus::blocking::connection::Builder::system(),
        };
        let connection = builder
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?
            .method_timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
        let proxy =
            zbus::blocking::Proxy::new(&connection, DBUS_DESTINATION, DBUS_PATH, DBUS_INTERFACE)
                .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
        proxy
            .call("GetNameOwner", &(self.destination.as_str(),))
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)
    }
}

pub(crate) fn open_recovery_owner_watches(
) -> Result<(OwnerWatch, OwnerWatch), SupervisorRecoveryError> {
    let systemd = systemd_owner(
        &zbus::blocking::connection::Builder::system()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?
            .method_timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?,
    )?;
    let logind = logind_owner()?;
    Ok((
        OwnerWatch::open(SYSTEMD_DESTINATION, systemd)?,
        OwnerWatch::open(LOGIND_DESTINATION, logind)?,
    ))
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) fn open_recovery_owner_watches_on_address(
    address: &str,
) -> Result<(OwnerWatch, OwnerWatch), SupervisorRecoveryError> {
    let connection = zbus::blocking::connection::Builder::address(address)
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    let dbus = zbus::blocking::Proxy::new(&connection, DBUS_DESTINATION, DBUS_PATH, DBUS_INTERFACE)
        .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
    let owner = |name: &str| {
        dbus.call::<_, _, String>("GetNameOwner", &(name,))
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)
    };
    Ok((
        OwnerWatch::open_on_address(
            SYSTEMD_DESTINATION,
            owner(SYSTEMD_DESTINATION)?,
            Some(address.to_owned()),
        )?,
        OwnerWatch::open_on_address(
            LOGIND_DESTINATION,
            owner(LOGIND_DESTINATION)?,
            Some(address.to_owned()),
        )?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_change_invalidates_authority_before_runtime_lookup() {
        let watch = OwnerWatch::scripted();
        watch.invalidate_for_test();
        assert!(watch.stable().is_err());
    }
}
