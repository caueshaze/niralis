
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
        let source = include_str!("verifier.rs");
        assert!(source.contains("GetUnitByInvocationID"));
        assert!(!source.contains("manager.call(\"GetUnit\""));
    }
}
