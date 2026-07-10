#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RealGraphicalSmokeGuardError {
    #[error("real graphical smoke requires NIRALIS_ALLOW_REAL_GRAPHICAL_SESSION=1")]
    NotAuthorized,
    #[error("real graphical smoke session id is not explicitly selected")]
    WrongSession,
    #[error("real graphical smoke watchdog is invalid")]
    InvalidWatchdog,
}

pub fn authorize_real_graphical_smoke(
    session_id: &str,
) -> Result<std::time::Duration, RealGraphicalSmokeGuardError> {
    if std::env::var("NIRALIS_ALLOW_REAL_GRAPHICAL_SESSION")
        .ok()
        .as_deref()
        != Some("1")
    {
        return Err(RealGraphicalSmokeGuardError::NotAuthorized);
    }
    if std::env::var("NIRALIS_REAL_GRAPHICAL_SESSION")
        .ok()
        .as_deref()
        != Some(session_id)
    {
        return Err(RealGraphicalSmokeGuardError::WrongSession);
    }
    let seconds = std::env::var("NIRALIS_REAL_GRAPHICAL_SMOKE_MAX_SECONDS")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| RealGraphicalSmokeGuardError::InvalidWatchdog)
        })
        .transpose()?
        .unwrap_or(300);
    if !(1..=3600).contains(&seconds) {
        return Err(RealGraphicalSmokeGuardError::InvalidWatchdog);
    }
    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke_guard_is_not_authorized_by_default() {
        std::env::remove_var("NIRALIS_ALLOW_REAL_GRAPHICAL_SESSION");
        std::env::remove_var("NIRALIS_REAL_GRAPHICAL_SESSION");
        assert!(super::authorize_real_graphical_smoke("niri").is_err());
    }
}
