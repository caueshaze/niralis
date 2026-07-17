use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::{PayloadScopeIdentity, PayloadScopeRecoveryReason};

const DESTINATION: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SCOPE_INTERFACE: &str = "org.freedesktop.systemd1.Scope";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeReleaseVerification {
    Released,
    RecoveryRequired(PayloadScopeRecoveryReason),
}

pub trait PayloadScopeReleaseVerifier: Send + Sync + std::fmt::Debug {
    fn verify(
        &self,
        identity: &PayloadScopeIdentity,
        deadline: Instant,
    ) -> ScopeReleaseVerification;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemdPayloadScopeReleaseVerifier;

impl PayloadScopeReleaseVerifier for SystemdPayloadScopeReleaseVerifier {
    fn verify(
        &self,
        identity: &PayloadScopeIdentity,
        deadline: Instant,
    ) -> ScopeReleaseVerification {
        verify_systemd(identity, deadline)
            .unwrap_or_else(ScopeReleaseVerification::RecoveryRequired)
    }
}

fn verify_systemd(
    identity: &PayloadScopeIdentity,
    deadline: Instant,
) -> Result<ScopeReleaseVerification, PayloadScopeRecoveryReason> {
    if !identity.validate() {
        return Ok(ScopeReleaseVerification::RecoveryRequired(
            PayloadScopeRecoveryReason::IdentityMismatch,
        ));
    }
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?
        .method_timeout(timeout.min(Duration::from_secs(5)))
        .build()
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let manager =
        zbus::blocking::Proxy::new(&connection, DESTINATION, MANAGER_PATH, MANAGER_INTERFACE)
            .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let invocation = parse_invocation_id(&identity.invocation_id)
        .ok_or(PayloadScopeRecoveryReason::IdentityMismatch)?;
    let expected_control_group = format!(
        "/user.slice/user-{}.slice/{}",
        identity.expected_uid, identity.unit_name
    );
    let first = resolve_by_invocation(&manager, &invocation)?;
    let first_observation = match &first {
        ResolvedInvocation::Present(path) => Some(read_observation(&connection, path)?),
        ResolvedInvocation::Missing => None,
    };
    let second = resolve_by_invocation(&manager, &invocation)?;
    match (&first, &second) {
        (ResolvedInvocation::Missing, ResolvedInvocation::Missing) => {
            return Ok(if boundary_absent(&expected_control_group)? {
                ScopeReleaseVerification::Released
            } else {
                ScopeReleaseVerification::RecoveryRequired(
                    PayloadScopeRecoveryReason::MembershipNotEmpty,
                )
            });
        }
        (ResolvedInvocation::Present(first_path), ResolvedInvocation::Present(second_path))
            if first_path == second_path => {}
        _ => {
            return Ok(ScopeReleaseVerification::RecoveryRequired(
                PayloadScopeRecoveryReason::InvocationIdMismatch,
            ));
        }
    }
    let object_path = match second {
        ResolvedInvocation::Present(path) => path,
        ResolvedInvocation::Missing => unreachable!(),
    };
    let observation = read_observation(&connection, &object_path)?;
    if first_observation.as_ref() != Some(&observation) {
        return Ok(ScopeReleaseVerification::RecoveryRequired(
            PayloadScopeRecoveryReason::IdentityMismatch,
        ));
    }
    if observation.id != identity.unit_name
        || observation.invocation_id != identity.invocation_id
        || observation.slice != format!("user-{}.slice", identity.expected_uid)
        || !observation.transient
        || (!observation.control_group.is_empty()
            && observation.control_group != expected_control_group)
    {
        return Ok(ScopeReleaseVerification::RecoveryRequired(
            PayloadScopeRecoveryReason::IdentityMismatch,
        ));
    }
    if !matches!(observation.active.as_str(), "inactive" | "failed")
        || !matches!(observation.sub.as_str(), "dead" | "failed" | "exited")
    {
        return Ok(ScopeReleaseVerification::RecoveryRequired(
            PayloadScopeRecoveryReason::UnitStillActive,
        ));
    }
    if !boundary_empty_or_absent(&expected_control_group)? {
        return Ok(ScopeReleaseVerification::RecoveryRequired(
            PayloadScopeRecoveryReason::MembershipNotEmpty,
        ));
    }
    Ok(ScopeReleaseVerification::Released)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedInvocation {
    Present(zbus::zvariant::OwnedObjectPath),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseObservation {
    id: String,
    invocation_id: String,
    active: String,
    sub: String,
    slice: String,
    control_group: String,
    transient: bool,
}

fn parse_invocation_id(value: &str) -> Option<Vec<u8>> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..16)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok())
        .collect()
}

fn resolve_by_invocation(
    manager: &zbus::blocking::Proxy<'_>,
    invocation: &[u8],
) -> Result<ResolvedInvocation, PayloadScopeRecoveryReason> {
    match manager.call("GetUnitByInvocationID", &(invocation.to_vec(),)) {
        Ok(path) => Ok(ResolvedInvocation::Present(path)),
        Err(zbus::Error::MethodError(name, _, _))
            if matches!(
                name.as_str(),
                "org.freedesktop.systemd1.NoSuchUnit" | "org.freedesktop.DBus.Error.UnknownObject"
            ) =>
        {
            Ok(ResolvedInvocation::Missing)
        }
        Err(_) => Err(PayloadScopeRecoveryReason::VerificationUnavailable),
    }
}
