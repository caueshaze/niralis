use std::ffi::{CStr, CString};
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{types::RuntimeSessionId, StartedSession};
use libloading::{Library, Symbol};
use tracing::{error, info, warn};
use zbus::zvariant::OwnedObjectPath;

pub(crate) const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
pub(crate) const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
pub(crate) const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
pub(crate) const SYSTEMD_UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
pub(crate) const SYSTEMD_SCOPE_INTERFACE: &str = "org.freedesktop.systemd1.Scope";
pub(crate) const LOGIND_DESTINATION: &str = "org.freedesktop.login1";
pub(crate) const LOGIND_MANAGER_PATH: &str = "/org/freedesktop/login1";
pub(crate) const LOGIND_MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
pub(crate) const LOGIND_SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
pub(crate) const DBUS_DESTINATION: &str = "org.freedesktop.DBus";
pub(crate) const DBUS_PATH: &str = "/org/freedesktop/DBus";
pub(crate) const DBUS_INTERFACE: &str = "org.freedesktop.DBus";
pub(crate) const CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub(crate) const MAX_CGROUP_FILE_BYTES: u64 = 64 * 1024;

mod boundary;
mod boundary_proof;
mod cgroup_observer;
mod cgroup_state;
mod coordinator;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
mod fixture_boundary;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
mod fixture_events;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
mod fixture_model;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
mod fixture_provider;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
mod fixture_startup;
mod linux_provider;
mod logind_cleanup;
mod logind_identity;
mod model;
mod owner_watch;
mod persistent;
mod persistent_operations;
mod persistent_validation;
mod provider;
mod record;
mod startup;
mod startup_linux;
mod startup_process;
mod startup_same_boot;
mod startup_same_boot_logind;
mod startup_same_boot_support;
mod systemd_dbus;
mod systemd_pin;
mod systemd_rehydrate;
#[cfg(test)]
mod tests;
mod unknown_scope;
mod vt;

pub(crate) use boundary::*;
pub(crate) use boundary_proof::*;
pub(crate) use cgroup_observer::*;
pub(crate) use cgroup_state::*;
pub(crate) use coordinator::*;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) use fixture_boundary::*;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) use fixture_events::*;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub use fixture_model::SupervisorFixtureBoundaryMode;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) use fixture_model::SupervisorFixtureCounters;
#[cfg(feature = "supervisor-test-fixtures")]
pub use fixture_model::SupervisorFixtureSnapshot;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) use fixture_provider::*;
#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
pub(crate) use fixture_startup::*;
pub(crate) use linux_provider::*;
pub(crate) use logind_cleanup::*;
pub(crate) use logind_identity::*;
pub(crate) use model::*;
pub(crate) use owner_watch::*;
pub(crate) use persistent::*;
pub(crate) use persistent_validation::*;
pub(crate) use provider::*;
pub(crate) use record::*;
pub(crate) use startup::*;
pub(crate) use startup_linux::*;
pub(crate) use startup_process::*;
pub(crate) use startup_same_boot::*;
pub(crate) use startup_same_boot_logind::*;
pub(crate) use startup_same_boot_support::*;
pub(crate) use systemd_dbus::*;
pub(crate) use systemd_pin::*;
pub(crate) use unknown_scope::*;
pub(crate) use vt::*;
