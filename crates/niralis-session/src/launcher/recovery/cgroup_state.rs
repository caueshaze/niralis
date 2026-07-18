use super::*;

pub(crate) fn read_pid_cgroup(pid: u32) -> Result<String, SupervisorRecoveryError> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)?;
    let mut unified = text.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = unified
        .next()
        .filter(|value| unified.next().is_none() && value.starts_with('/'))
        .ok_or(SupervisorRecoveryError::InvalidPayloadIdentity)?;
    Ok(value.to_owned())
}

pub(crate) fn ensure_outside_boundary(
    pid: u32,
    boundary: &str,
) -> Result<(), SupervisorRecoveryError> {
    match read_pid_cgroup(pid) {
        Ok(value) if value == boundary || value.starts_with(&format!("{boundary}/")) => {
            Err(SupervisorRecoveryError::InvalidPayloadIdentity)
        }
        Ok(_) => Ok(()),
        Err(_) if !Path::new(&format!("/proc/{pid}")).exists() => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) fn cgroup_path(control_group: &str) -> Result<PathBuf, SupervisorRecoveryError> {
    if !control_group.starts_with('/') || control_group.contains("..") {
        return Err(SupervisorRecoveryError::InvalidPayloadIdentity);
    }
    Ok(Path::new(CGROUP_ROOT).join(control_group.trim_start_matches('/')))
}

pub(crate) fn read_supervisor_boundary_state(
    control_group: &str,
) -> Result<SupervisorBoundaryState, SupervisorRecoveryError> {
    let path = cgroup_path(control_group)?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SupervisorBoundaryState::Absent)
        }
        Ok(metadata) if metadata.is_dir() => {}
        _ => return Err(SupervisorRecoveryError::InvalidPayloadIdentity),
    }
    let events = read_bounded_file(&path.join("cgroup.events"))?;
    let populated =
        parse_populated(&events).ok_or(SupervisorRecoveryError::InvalidPayloadIdentity)?;
    let procs = read_bounded_file(&path.join("cgroup.procs"))?;
    if populated != 0 || procs.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Ok(SupervisorBoundaryState::Populated);
    }
    for entry in fs::read_dir(&path).map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)? {
        let entry = entry.map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)?;
        if entry
            .file_type()
            .map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)?
            .is_dir()
            && !matches!(
                read_supervisor_boundary_state_from_path(&entry.path())?,
                SupervisorBoundaryState::Empty | SupervisorBoundaryState::Absent
            )
        {
            return Ok(SupervisorBoundaryState::Populated);
        }
    }
    Ok(SupervisorBoundaryState::Empty)
}

pub(crate) fn read_supervisor_boundary_state_from_path(
    path: &Path,
) -> Result<SupervisorBoundaryState, SupervisorRecoveryError> {
    let events = read_bounded_file(&path.join("cgroup.events"))?;
    let procs = read_bounded_file(&path.join("cgroup.procs"))?;
    if parse_populated(&events) != Some(0) || procs.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Ok(SupervisorBoundaryState::Populated);
    }
    for entry in fs::read_dir(path).map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)? {
        let entry = entry.map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)?;
        if entry
            .file_type()
            .map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)?
            .is_dir()
            && read_supervisor_boundary_state_from_path(&entry.path())?
                == SupervisorBoundaryState::Populated
        {
            return Ok(SupervisorBoundaryState::Populated);
        }
    }
    Ok(SupervisorBoundaryState::Empty)
}

pub(crate) fn read_bounded_file(path: &Path) -> Result<Vec<u8>, SupervisorRecoveryError> {
    let file = fs::File::open(path).map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)?;
    let mut bytes = Vec::new();
    file.take(MAX_CGROUP_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)?;
    if bytes.len() as u64 > MAX_CGROUP_FILE_BYTES {
        return Err(SupervisorRecoveryError::InvalidPayloadIdentity);
    }
    Ok(bytes)
}

pub(crate) fn parse_populated(bytes: &[u8]) -> Option<u8> {
    let text = std::str::from_utf8(bytes).ok()?;
    let values = text.lines().filter_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        match (fields.next(), fields.next(), fields.next()) {
            (Some("populated"), Some(value), None) => value.parse::<u8>().ok(),
            _ => None,
        }
    });
    let values: Vec<u8> = values.collect();
    match values.as_slice() {
        [value @ 0..=1] => Some(*value),
        _ => None,
    }
}

pub(crate) fn read_process_credentials(pid: u32) -> Result<(u32, u32), SupervisorRecoveryError> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| SupervisorRecoveryError::InvalidPayloadIdentity)?;
    let parse = |prefix: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|line| line.split_ascii_whitespace().next())
            .and_then(|value| value.parse::<u32>().ok())
    };
    match (parse("Uid:"), parse("Gid:")) {
        (Some(uid), Some(gid)) if uid != 0 && gid != 0 => Ok((uid, gid)),
        _ => Err(SupervisorRecoveryError::InvalidPayloadIdentity),
    }
}
