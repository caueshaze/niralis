use crate::{types::RuntimeSessionId, StartedSession};
use libloading::{Library, Symbol};
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
mod fixture_dbus;
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
mod fixture_logind;
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
mod fixture_process_cgroup;
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
mod logind_recovery_effects;
mod model;
mod owner_watch;
mod owner_watch_authority;
mod owner_watch_open;
#[cfg(test)]
mod owner_watch_tests;
mod persistent;
mod persistent_operations;
mod persistent_record_set;
mod persistent_taxonomy;
mod persistent_validation;
mod persistent_validation_helpers;
mod previous_boot;
mod previous_boot_finalization;
mod previous_boot_finalization_storage;
mod previous_boot_inspection;
mod previous_boot_linux_facts;
mod previous_boot_linux_host;
mod previous_boot_linux_vt;
#[cfg(feature = "supervisor-test-fixtures")]
mod previous_boot_physical_smoke;
mod provider;
mod record;
mod recovery_capabilities;
mod recovery_finalization;
mod recovery_finalization_free;
mod recovery_finalization_tail;
mod recovery_proofs;
mod recovery_startup_finalization;
#[cfg(test)]
mod recovery_transition_tests;
mod recovery_transitions;
mod startup;
mod startup_absent_boundary;
mod startup_linux;
mod startup_process;
mod startup_quarantine;
mod startup_same_boot;
mod startup_same_boot_logind;
mod startup_same_boot_payload;
mod startup_same_boot_support;
#[cfg(test)]
mod startup_tests;
mod startup_vt_recovery;
mod systemd_dbus;
mod systemd_pin;
mod systemd_pin_live;
mod systemd_rehydrate;
#[cfg(test)]
mod tests;
mod unknown_scope;
mod vt;
mod vt_admin_effects;
mod vt_busy;
mod vt_busy_holders;
mod vt_busy_support;
#[cfg(all(test, feature = "vt-integration-tests"))]
mod vt_integration_tests;
mod vt_recovery_effects;
mod vt_verification;
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
pub(crate) use fixture_dbus::*;
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
pub(crate) use fixture_logind::*;
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
pub(crate) use fixture_process_cgroup::*;
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
pub(crate) use persistent::*;
pub(crate) use persistent_taxonomy::*;
pub(crate) use persistent_validation::*;
pub(crate) use persistent_validation_helpers::*;
pub(crate) use previous_boot::*;
pub(crate) use previous_boot_finalization::*;
pub(crate) use previous_boot_finalization_storage::*;
pub(crate) use previous_boot_inspection::*;
pub(crate) use previous_boot_linux_host::*;
#[cfg(feature = "supervisor-test-fixtures")]
pub use previous_boot_physical_smoke::*;
pub(crate) use provider::*;
pub(crate) use record::*;
pub(crate) use recovery_capabilities::*;
pub(crate) use recovery_finalization::*;
pub(crate) use recovery_proofs::*;
pub(crate) use startup::*;
pub(crate) use startup_absent_boundary::*;
pub(crate) use startup_linux::*;
pub(crate) use startup_process::*;
pub(crate) use startup_quarantine::*;
pub(crate) use startup_same_boot::*;
pub(crate) use startup_same_boot_logind::*;
pub(crate) use startup_same_boot_payload::*;
pub(crate) use startup_same_boot_support::*;
pub(crate) use startup_vt_recovery::*;
pub(crate) use systemd_dbus::*;
pub(crate) use systemd_pin::*;
pub(crate) use systemd_rehydrate::*;
pub(crate) use unknown_scope::*;
pub(crate) use {
    linux_provider::*, logind_cleanup::*, logind_identity::*, logind_recovery_effects::*, model::*,
    owner_watch::*, owner_watch_authority::*, owner_watch_open::*,
};
pub(crate) use {vt::*, vt_admin_effects::*, vt_busy::*, vt_recovery_effects::*};
