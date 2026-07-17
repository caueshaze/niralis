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

fn read_observation(
    connection: &zbus::blocking::Connection,
    object_path: &zbus::zvariant::OwnedObjectPath,
) -> Result<ReleaseObservation, PayloadScopeRecoveryReason> {
    let unit = zbus::blocking::Proxy::new(
        connection,
        DESTINATION,
        object_path.as_str(),
        UNIT_INTERFACE,
    )
    .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let scope = zbus::blocking::Proxy::new(
        connection,
        DESTINATION,
        object_path.as_str(),
        SCOPE_INTERFACE,
    )
    .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let id: String = unit
        .get_property("Id")
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let invocation: Vec<u8> = unit
        .get_property("InvocationID")
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let active: String = unit
        .get_property("ActiveState")
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let sub: String = unit
        .get_property("SubState")
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let transient: bool = unit
        .get_property("Transient")
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let slice: String = scope
        .get_property("Slice")
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let control_group: String = scope
        .get_property("ControlGroup")
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let observed_invocation = invocation
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if invocation.len() != 16 {
        return Err(PayloadScopeRecoveryReason::IdentityMismatch);
    }
    Ok(ReleaseObservation {
        id,
        invocation_id: observed_invocation,
        active,
        sub,
        slice,
        control_group,
        transient,
    })
}

fn boundary_path(control_group: &str) -> std::path::PathBuf {
    Path::new("/sys/fs/cgroup").join(control_group.trim_start_matches('/'))
}

fn boundary_absent(control_group: &str) -> Result<bool, PayloadScopeRecoveryReason> {
    match fs::symlink_metadata(boundary_path(control_group)) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(_) => Err(PayloadScopeRecoveryReason::VerificationUnavailable),
    }
}

fn boundary_empty_or_absent(control_group: &str) -> Result<bool, PayloadScopeRecoveryReason> {
    let path = boundary_path(control_group);
    match fs::read_to_string(path.join("cgroup.procs")) {
        Ok(members) => Ok(!members.lines().any(|line| !line.is_empty())),
        Err(error) if error.kind() == ErrorKind::NotFound => boundary_absent(control_group),
        Err(_) => Err(PayloadScopeRecoveryReason::VerificationUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LogindSessionId;

    fn identity() -> PayloadScopeIdentity {
        PayloadScopeIdentity {
            unit_name: "niralis-payload-release-test.scope".into(),
            invocation_id: "0123456789abcdef0123456789abcdef".into(),
            expected_uid: 1000,
            logind_session_id: LogindSessionId::new("c1".into()).unwrap(),
        }
    }

    #[test]
    fn invalid_identity_is_recovery_required_without_bus_access() {
        let mut value = identity();
        value.unit_name = "session-3.scope".into();
        assert_eq!(
            SystemdPayloadScopeReleaseVerifier
                .verify(&value, Instant::now() + Duration::from_secs(1)),
            ScopeReleaseVerification::RecoveryRequired(
                PayloadScopeRecoveryReason::IdentityMismatch
            )
        );
    }

    #[test]
    fn expired_deadline_is_verification_unavailable() {
        let result = SystemdPayloadScopeReleaseVerifier
            .verify(&identity(), Instant::now() - Duration::from_secs(1));
        assert_eq!(
            result,
            ScopeReleaseVerification::RecoveryRequired(
                PayloadScopeRecoveryReason::VerificationUnavailable
            )
        );
    }

    #[test]
    fn release_verifier_is_invocation_bound_and_never_resolves_by_name() {
        let source = include_str!("scope_release.rs");
        assert!(source.contains("GetUnitByInvocationID"));
        assert!(!source.contains("manager.call(\"GetUnit\""));
    }
}
