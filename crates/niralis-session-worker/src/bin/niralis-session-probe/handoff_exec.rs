
fn read_handoff() -> Result<SessionProbeHandoff, ()> {
    let mut file = unsafe { std::fs::File::from_raw_fd(PROBE_HANDOFF_FD) };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(());
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn read_commit() -> bool {
    let mut input = std::io::stdin().lock();
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while bytes.len() <= 1024 * 1024 {
        if input.read_exact(&mut byte).is_err() {
            return false;
        }
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if bytes.len() > 1024 * 1024 || bytes.last() != Some(&b'\n') {
        return false;
    }
    matches!(
        serde_json::from_slice::<SessionChildEnvelope<SessionChildCommit>>(&bytes[..bytes.len() - 1]),
        Ok(commit)
            if commit.version == SESSION_CHILD_PROTOCOL_VERSION
                && matches!(commit.message, SessionChildCommit::Exec)
    )
}

fn write_final_exec_failure(stage: &str) {
    let failure = FinalExecFailure {
        stage: stage.to_owned(),
        errno: std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    };
    if let Ok(bytes) = serde_json::to_vec(&failure) {
        unsafe {
            libc::write(4, bytes.as_ptr().cast(), bytes.len());
        }
    }
}

fn exec_final(plan: &niralis_session::SessionExecPlan) -> Result<(), ()> {
    plan.validate()?;
    let executable_path =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(plan.executable.clone()));
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(&executable_path).map_err(|_| ())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(());
    }
    let executable = std::ffi::CString::new(plan.executable.clone()).map_err(|_| ())?;
    let args = plan
        .argv
        .iter()
        .map(|arg| std::ffi::CString::new(arg.clone()).map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv = args.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    argv.push(std::ptr::null());
    let mut environment = Vec::new();
    for (key, value) in std::env::vars_os() {
        use std::os::unix::ffi::OsStrExt;
        let mut bytes = key.as_os_str().as_bytes().to_vec();
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_os_str().as_bytes());
        environment.push(std::ffi::CString::new(bytes).map_err(|_| ())?);
    }
    let mut envp = environment
        .iter()
        .map(|entry| entry.as_ptr())
        .collect::<Vec<_>>();
    envp.push(std::ptr::null());
    if unsafe { libc::execve(executable.as_ptr(), argv.as_ptr(), envp.as_ptr()) } == -1 {
        Err(())
    } else {
        Ok(())
    }
}
