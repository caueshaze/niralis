
fn validate_disappeared_boundary_properties(
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    properties: &InvocationUnitProperties,
) -> Result<(), PayloadScopeError> {
    if properties.object_path != pinned.object_path
        || properties.invocation_id != identity.invocation_id
        || properties.id != identity.unit_name
        || properties.slice != format!("user-{}.slice", identity.expected_uid)
        || !properties.transient
        || (!properties.control_group.is_empty() && properties.control_group != control_group)
        || !terminal_unit_state(&properties.active_state, &properties.sub_state)
    {
        return Err(PayloadScopeError::UnitReplaced);
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, PayloadScopeError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(PayloadScopeError::TimedOut)
}

fn random_id() -> Result<String, PayloadScopeError> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| PayloadScopeError::StartFailed)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn hex_id(bytes: &[u8]) -> Option<String> {
    (bytes.len() == 16).then(|| bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn parse_hex_id(value: &str) -> Option<Vec<u8>> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..16)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok())
        .collect()
}

fn valid_slice_name(value: &str, uid: u32) -> bool {
    value == format!("user-{uid}.slice") && uid != 0
}

fn valid_payload_cgroup(cgroup: &str, uid: u32, unit: &str) -> bool {
    cgroup == format!("/user.slice/user-{uid}.slice/{unit}")
        && unit.starts_with("niralis-payload-")
        && unit.ends_with(".scope")
}

fn is_ancestor(candidate: &str, path: &str) -> bool {
    path.strip_prefix(candidate)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn cgroup_file(cgroup: &str) -> Result<PathBuf, PayloadScopeError> {
    cgroup_file_named(cgroup, "cgroup.procs")
}

fn cgroup_file_named(cgroup: &str, name: &str) -> Result<PathBuf, PayloadScopeError> {
    if !cgroup.starts_with('/') || cgroup.contains("..") {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    Ok(Path::new(CGROUP_ROOT)
        .join(cgroup.trim_start_matches('/'))
        .join(name))
}

fn read_members(cgroup: &str) -> Result<Vec<u32>, PayloadScopeError> {
    let text = fs::read_to_string(cgroup_file(cgroup)?)
        .map_err(|_| PayloadScopeError::InvalidMembership)?;
    let mut members = text
        .lines()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PayloadScopeError::InvalidMembership)?;
    members.sort_unstable();
    Ok(members)
}

fn pid_cgroup(pid: u32) -> Result<String, PayloadScopeError> {
    parse_unified_cgroup(
        &fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map_err(|_| PayloadScopeError::CgroupMismatch)?,
    )
}

fn pidfd_cgroup(pidfd: RawFd) -> Result<String, PayloadScopeError> {
    type SdPidfdGetCgroup =
        unsafe extern "C" fn(libc::c_int, *mut *mut libc::c_char) -> libc::c_int;
    let library = unsafe { libloading::Library::new("libsystemd.so.0") }
        .map_err(|_| PayloadScopeError::CgroupMismatch)?;
    let function: libloading::Symbol<SdPidfdGetCgroup> =
        unsafe { library.get(b"sd_pidfd_get_cgroup\0") }
            .map_err(|_| PayloadScopeError::CgroupMismatch)?;
    let mut raw = std::ptr::null_mut();
    let result = unsafe { function(pidfd, &mut raw) };
    if result < 0 || raw.is_null() {
        return Err(PayloadScopeError::CgroupMismatch);
    }
    let value = unsafe { std::ffi::CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    unsafe { libc::free(raw.cast()) };
    Ok(value)
}

fn parse_unified_cgroup(text: &str) -> Result<String, PayloadScopeError> {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_owned)
        .ok_or(PayloadScopeError::CgroupMismatch)
}

