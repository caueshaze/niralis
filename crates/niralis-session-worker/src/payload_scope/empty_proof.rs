
async fn prove_empty_boundary(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &PinnedInvocationUnit,
    control_group: &str,
    worker_pid: u32,
    launcher_pid: u32,
    leader_exit: &crate::termination::LeaderExit,
) -> Result<crate::termination::BoundaryEmptyProof, PayloadScopeError> {
    info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, "verifying payload boundary emptiness");
    if !valid_payload_cgroup(control_group, identity.expected_uid, &identity.unit_name) {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    let first = resolve_invocation_for_proof(provider, &identity.invocation_id).await?;
    if let ResolvedInvocationState::Present(path) = &first {
        validate_terminal_unit(provider, identity, pinned, control_group, path).await?;
    }

    match provider
        .read_boundary_state(&identity.invocation_id, &pinned.object_path, control_group)
        .map_err(|error| map_invocation_error(InvocationOperation::ReadBoundaryState, error))?
    {
        CgroupEmptyState::Absent => {}
        CgroupEmptyState::PresentEmpty => {}
    }
    for outside_pid in [worker_pid, launcher_pid] {
        if let Ok(path) = pid_cgroup(outside_pid) {
            if path == control_group || is_ancestor(control_group, &path) {
                return Err(PayloadScopeError::WorkerInsideBoundary);
            }
        }
    }
    let second = resolve_invocation_for_proof(provider, &identity.invocation_id).await?;
    match (&first, &second) {
        (ResolvedInvocationState::Present(first_path), ResolvedInvocationState::Present(path))
            if first_path == path =>
        {
            validate_terminal_unit(provider, identity, pinned, control_group, path).await?
        }
        (ResolvedInvocationState::Missing, ResolvedInvocationState::Missing) => {}
        _ => return Err(PayloadScopeError::UnitReplaced),
    }
    info!(unit = %identity.unit_name, invocation_id = %identity.invocation_id, "payload boundary empty proof established");
    Ok(crate::termination::BoundaryEmptyProof::new(
        identity,
        control_group,
        leader_exit.clone(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CgroupEmptyState {
    Absent,
    PresentEmpty,
}

fn read_cgroup_empty_state(control_group: &str) -> Result<CgroupEmptyState, PayloadScopeError> {
    read_cgroup_empty_state_at(Path::new(CGROUP_ROOT), control_group)
}

fn read_cgroup_empty_state_at(
    root: &Path,
    control_group: &str,
) -> Result<CgroupEmptyState, PayloadScopeError> {
    if !control_group.starts_with('/') || control_group.contains("..") {
        return Err(PayloadScopeError::InvalidIdentity);
    }
    let directory = root.join(control_group.trim_start_matches('/'));
    let events_path = directory.join("cgroup.events");
    match fs::symlink_metadata(&events_path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Err(PayloadScopeError::InvalidMembership),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match fs::symlink_metadata(&directory) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(CgroupEmptyState::Absent)
                }
                _ => Err(PayloadScopeError::InvalidMembership),
            };
        }
        Err(_) => return Err(PayloadScopeError::InvalidMembership),
    }
    let events = read_bounded(&events_path)?;
    if parse_populated(&events)? != 0 {
        return Err(PayloadScopeError::BoundaryNotEmpty);
    }
    let procs = read_bounded(&directory.join("cgroup.procs"))?;
    if !procs.trim().is_empty() {
        return Err(PayloadScopeError::BoundaryNotEmpty);
    }
    Ok(CgroupEmptyState::PresentEmpty)
}

fn read_bounded(path: &Path) -> Result<String, PayloadScopeError> {
    let file = fs::File::open(path).map_err(|_| PayloadScopeError::InvalidMembership)?;
    let mut bytes = Vec::new();
    file.take(MAX_CGROUP_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PayloadScopeError::InvalidMembership)?;
    if bytes.len() as u64 > MAX_CGROUP_STATE_BYTES {
        return Err(PayloadScopeError::InvalidMembership);
    }
    String::from_utf8(bytes).map_err(|_| PayloadScopeError::InvalidMembership)
}

fn parse_populated(text: &str) -> Result<u8, PayloadScopeError> {
    let mut populated = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(key) = fields.next() else { continue };
        let Some(value) = fields.next() else {
            return Err(PayloadScopeError::InvalidMembership);
        };
        if fields.next().is_some() {
            return Err(PayloadScopeError::InvalidMembership);
        }
        if key == "populated" {
            if populated.is_some() {
                return Err(PayloadScopeError::InvalidMembership);
            }
            populated = Some(
                value
                    .parse::<u8>()
                    .ok()
                    .filter(|value| *value <= 1)
                    .ok_or(PayloadScopeError::InvalidMembership)?,
            );
        }
    }
    populated.ok_or(PayloadScopeError::InvalidMembership)
}

async fn release_pin(
    provider: &dyn InvocationBoundProvider,
    identity: &PayloadScopeIdentity,
    pinned: &mut PinnedInvocationUnit,
) -> Result<(), PayloadScopeError> {
    if !pinned.reference_held {
        return Ok(());
    }
    provider
        .unref_pinned_unit(&identity.invocation_id, &pinned.object_path)
        .await
        .map_err(|error| {
            let mapped = map_invocation_error(InvocationOperation::UnrefPinnedUnit, error);
            warn!(?mapped, "pinned unit reference release failed");
            PayloadScopeError::UnrefFailed
        })?;
    pinned.reference_held = false;
    Ok(())
}

impl PayloadScopeManager for SystemdPayloadScopeManager {
    fn prepare(
        &self,
        report: &SessionChildReport,
        authoritative_pidfd: RawFd,
        expected_uid: u32,
        logind_session_id: &LogindSessionId,
        worker_pid: u32,
        launcher_pid: u32,
        deadline: Instant,
    ) -> Result<Box<dyn AuthoritativePayloadScope>, PayloadScopeError> {
        if expected_uid == 0
            || report.child_pid != report.process_identity.pid
            || report.process_identity.sid != report.child_pid
            || report.process_identity.pgid != report.child_pid
            || authoritative_pidfd < 0
        {
            return Err(PayloadScopeError::InvalidIdentity);
        }
        async_io::block_on(prepare_scope(
            report.child_pid,
            authoritative_pidfd,
            expected_uid,
            logind_session_id,
            worker_pid,
            launcher_pid,
            deadline,
        ))
        .map(|scope| Box::new(scope) as Box<dyn AuthoritativePayloadScope>)
    }
}
