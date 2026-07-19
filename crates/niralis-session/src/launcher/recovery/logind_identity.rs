use super::*;

pub(crate) fn resolve_logind_identity(
    payload_identity: &crate::PayloadScopeIdentity,
) -> Result<SupervisorLogindSessionIdentity, SupervisorRecoveryError> {
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?
        .method_timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        LOGIND_DESTINATION,
        LOGIND_MANAGER_PATH,
        LOGIND_MANAGER_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let path: OwnedObjectPath = manager
        .call(
            "GetSession",
            &(payload_identity.logind_session_id.as_str(),),
        )
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    read_logind_identity(
        &connection,
        &path,
        payload_identity.logind_session_id.clone(),
    )
}

pub(crate) fn logind_session_exists(id: &str) -> Result<bool, SupervisorRecoveryError> {
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        LOGIND_DESTINATION,
        LOGIND_MANAGER_PATH,
        LOGIND_MANAGER_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    match manager.call::<_, _, OwnedObjectPath>("GetSession", &(id,)) {
        Ok(_) => Ok(true),
        Err(zbus::Error::MethodError(name, _, _))
            if matches!(
                name.as_str(),
                "org.freedesktop.login1.NoSuchSession" | "org.freedesktop.DBus.Error.UnknownObject"
            ) =>
        {
            Ok(false)
        }
        Err(_) => Err(SupervisorRecoveryError::LogindUnavailable),
    }
}

pub(crate) fn logind_owner() -> Result<String, SupervisorRecoveryError> {
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?
        .method_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let dbus = zbus::blocking::Proxy::new(&connection, DBUS_DESTINATION, DBUS_PATH, DBUS_INTERFACE)
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    dbus.call("GetNameOwner", &(LOGIND_DESTINATION,))
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)
}

pub(crate) fn resolve_logind_identity_by_leader(
    worker_pid: u32,
    expected_desktop: &str,
) -> Result<SupervisorLogindSessionIdentity, SupervisorRecoveryError> {
    let connection = zbus::blocking::connection::Builder::system()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?
        .method_timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        LOGIND_DESTINATION,
        LOGIND_MANAGER_PATH,
        LOGIND_MANAGER_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let sessions: Vec<(String, u32, String, String, OwnedObjectPath)> = manager
        .call("ListSessions", &())
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let mut matched = None;
    for (id, listed_uid, _username, listed_seat, path) in sessions {
        let Some(id) = crate::LogindSessionId::new(id) else {
            return Err(SupervisorRecoveryError::LogindIdentityChanged);
        };
        let session = zbus::blocking::Proxy::new(
            &connection,
            LOGIND_DESTINATION,
            path.as_str(),
            LOGIND_SESSION_INTERFACE,
        )
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
        let leader: u32 = session
            .get_property("Leader")
            .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
        if leader != worker_pid {
            continue;
        }
        let identity = read_logind_identity(&connection, &path, id)?;
        if identity.uid != listed_uid
            || identity.seat != listed_seat
            || identity.seat != "seat0"
            || (!identity.desktop.is_empty() && identity.desktop != expected_desktop)
            || matched.is_some()
        {
            return Err(SupervisorRecoveryError::LogindIdentityChanged);
        }
        matched = Some(identity);
    }
    matched.ok_or(SupervisorRecoveryError::InvalidRecord)
}

pub(crate) fn read_logind_identity(
    connection: &zbus::blocking::Connection,
    path: &OwnedObjectPath,
    id: crate::LogindSessionId,
) -> Result<SupervisorLogindSessionIdentity, SupervisorRecoveryError> {
    let session = zbus::blocking::Proxy::new(
        connection,
        LOGIND_DESTINATION,
        path.as_str(),
        LOGIND_SESSION_INTERFACE,
    )
    .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let observed_id: String = session
        .get_property("Id")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let (uid, _user_path): (u32, OwnedObjectPath) = session
        .get_property("User")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let leader: u32 = session
        .get_property("Leader")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let username: String = session
        .get_property("Name")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let (seat, _seat_path): (String, OwnedObjectPath) = session
        .get_property("Seat")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let vt_number: u32 = session
        .get_property("VTNr")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let session_type: String = session
        .get_property("Type")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let class: String = session
        .get_property("Class")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let desktop: String = session.get_property("Desktop").unwrap_or_default();
    let state: String = session
        .get_property("State")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    let scope: String = session
        .get_property("Scope")
        .map_err(|_| SupervisorRecoveryError::LogindUnavailable)?;
    if observed_id != id.as_str()
        || uid == 0
        || leader == 0
        || username.is_empty()
        || seat.is_empty()
        || vt_number == 0
        || !matches!(session_type.as_str(), "wayland" | "x11")
        || class != "user"
        || state.is_empty()
        || scope.is_empty()
    {
        warn!(
            expected_session_id = %id.as_str(),
            observed_session_id = %observed_id,
            observed_uid = uid,
            observed_logind_leader_pid = leader,
            observed_seat = %seat,
            observed_vt = vt_number,
            observed_type = %session_type,
            observed_class = %class,
            observed_state = %state,
            has_scope = !scope.is_empty(),
            "supervisor rejected incomplete logind session identity"
        );
        return Err(SupervisorRecoveryError::LogindIdentityChanged);
    }
    Ok(SupervisorLogindSessionIdentity {
        id,
        object_path: path.to_string(),
        uid,
        username,
        leader,
        seat,
        vt_number,
        session_type,
        class,
        desktop,
        state,
        scope,
    })
}
