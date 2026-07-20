use super::*;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthorityWatchState {
    Stable {
        unique_owner: String,
        generation: u64,
    },
    Changed {
        previous_owner: String,
        current_owner: String,
        generation: u64,
    },
    Lost {
        generation: u64,
    },
}

#[derive(Debug)]
pub(crate) struct OwnerWatch {
    destination: String,
    state: Arc<Mutex<AuthorityWatchState>>,
    generation: Arc<AtomicU64>,
    event: OwnedFd,
    address: Option<String>,
}

impl OwnerWatch {
    #[cfg_attr(not(any(test, feature = "supervisor-test-fixtures")), allow(dead_code))]
    pub(crate) fn scripted() -> Self {
        let event = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        Self {
            destination: "test.owner".to_owned(),
            state: Arc::new(Mutex::new(AuthorityWatchState::Stable {
                unique_owner: "test.owner".to_owned(),
                generation: 0,
            })),
            generation: Arc::new(AtomicU64::new(0)),
            event: unsafe { OwnedFd::from_raw_fd(event) },
            address: None,
        }
    }

    #[cfg_attr(not(any(test, feature = "supervisor-test-fixtures")), allow(dead_code))]
    pub(crate) fn invalidate_for_test(&self) {
        self.invalidate("test.owner".to_owned(), "test.owner.replaced".to_owned());
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
        let state = Arc::new(Mutex::new(AuthorityWatchState::Stable {
            unique_owner: initial_owner.clone(),
            generation: 0,
        }));
        let generation = Arc::new(AtomicU64::new(0));
        let thread_state = Arc::clone(&state);
        let thread_generation = Arc::clone(&generation);
        let thread_initial_owner = initial_owner.clone();
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
                let builder = match &thread_address {
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
                    let generation = thread_generation.fetch_add(1, Ordering::AcqRel) + 1;
                    let current_owner = current_owner_on_address(&name, thread_address.as_deref());
                    if let Ok(mut state) = thread_state.lock() {
                        *state = match current_owner {
                            Ok(current_owner) => AuthorityWatchState::Changed {
                                previous_owner: thread_initial_owner,
                                current_owner,
                                generation,
                            },
                            Err(()) => AuthorityWatchState::Lost { generation },
                        };
                    }
                    let value = 1u64.to_ne_bytes();
                    let _ = unsafe {
                        libc::write(thread_event.as_raw_fd(), value.as_ptr().cast(), value.len())
                    };
                }
            })
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
        Ok(Self {
            destination: destination.to_owned(),
            state,
            generation,
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
            self.mark_lost();
        }
        let state = self
            .state()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?;
        let AuthorityWatchState::Stable { unique_owner, .. } = state else {
            return Err(SupervisorRecoveryError::BusUnavailable);
        };
        match self.current_owner() {
            Ok(current_owner) if current_owner == unique_owner => Ok(()),
            Ok(current_owner) => {
                self.invalidate(unique_owner, current_owner);
                Err(SupervisorRecoveryError::BusUnavailable)
            }
            Err(error) => {
                self.mark_lost();
                Err(error)
            }
        }
    }

    pub(crate) fn event_fd(&self) -> i32 {
        self.event.as_raw_fd()
    }

    pub(crate) fn state(&self) -> Result<AuthorityWatchState, ()> {
        self.state.lock().map(|state| state.clone()).map_err(|_| ())
    }

    fn invalidate(&self, previous_owner: String, current_owner: String) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        if let Ok(mut state) = self.state.lock() {
            if matches!(*state, AuthorityWatchState::Stable { .. }) {
                *state = AuthorityWatchState::Changed {
                    previous_owner,
                    current_owner,
                    generation,
                };
            }
        }
    }

    fn mark_lost(&self) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        if let Ok(mut state) = self.state.lock() {
            if matches!(*state, AuthorityWatchState::Stable { .. }) {
                *state = AuthorityWatchState::Lost { generation };
            }
        }
    }

    fn current_owner(&self) -> Result<String, SupervisorRecoveryError> {
        current_owner_on_address(&self.destination, self.address.as_deref())
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)
    }
}

fn current_owner_on_address(destination: &str, address: Option<&str>) -> Result<String, ()> {
    let builder = match address {
        Some(address) => zbus::blocking::connection::Builder::address(address),
        None => zbus::blocking::connection::Builder::system(),
    };
    let connection = builder
        .map_err(|_| ())?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| ())?;
    let proxy =
        zbus::blocking::Proxy::new(&connection, DBUS_DESTINATION, DBUS_PATH, DBUS_INTERFACE)
            .map_err(|_| ())?;
    proxy.call("GetNameOwner", &(destination,)).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_change_invalidates_authority_before_runtime_lookup() {
        let watch = OwnerWatch::scripted();
        watch.invalidate_for_test();
        assert!(watch.stable().is_err());
        assert!(matches!(
            watch.state().unwrap(),
            AuthorityWatchState::Changed { generation: 1, .. }
        ));
    }
}
