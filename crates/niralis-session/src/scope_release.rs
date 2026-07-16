use std::fs;
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
    let object_path: zbus::zvariant::OwnedObjectPath =
        match manager.call("GetUnit", &(identity.unit_name.as_str(),)) {
            Ok(path) => path,
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
            {
                return Ok(ScopeReleaseVerification::Released);
            }
            Err(_) => return Err(PayloadScopeRecoveryReason::VerificationUnavailable),
        };
    let unit = zbus::blocking::Proxy::new(
        &connection,
        DESTINATION,
        object_path.as_str(),
        UNIT_INTERFACE,
    )
    .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let scope = zbus::blocking::Proxy::new(
        &connection,
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
    let slice: String = scope
        .get_property("Slice")
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    let control_group: String = scope
        .get_property("ControlGroup")
        .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    if id != identity.unit_name
        || slice != format!("user-{}.slice", identity.expected_uid)
        || control_group
            != format!(
                "/user.slice/user-{}.slice/{}",
                identity.expected_uid, identity.unit_name
            )
    {
        return Ok(ScopeReleaseVerification::RecoveryRequired(
            PayloadScopeRecoveryReason::IdentityMismatch,
        ));
    }
    let observed_invocation = invocation
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if invocation.len() != 16 || observed_invocation != identity.invocation_id {
        return Ok(ScopeReleaseVerification::RecoveryRequired(
            PayloadScopeRecoveryReason::InvocationIdMismatch,
        ));
    }
    let members = fs::read_to_string(
        Path::new("/sys/fs/cgroup")
            .join(control_group.trim_start_matches('/'))
            .join("cgroup.procs"),
    )
    .map_err(|_| PayloadScopeRecoveryReason::VerificationUnavailable)?;
    if members.lines().any(|line| !line.is_empty()) {
        return Ok(ScopeReleaseVerification::RecoveryRequired(
            PayloadScopeRecoveryReason::MembershipNotEmpty,
        ));
    }
    if !matches!(active.as_str(), "inactive" | "failed")
        || !matches!(sub.as_str(), "dead" | "failed" | "exited")
    {
        return Ok(ScopeReleaseVerification::RecoveryRequired(
            PayloadScopeRecoveryReason::UnitStillActive,
        ));
    }
    Ok(ScopeReleaseVerification::Released)
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
}
