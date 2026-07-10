use niralis_session_worker::{
    LinuxPostDropAuditor, PostDropAuditor, SessionChildEnvelope, SessionChildIsolationProof,
    SessionChildResponse, SessionChildUnixCredentials, SessionChildUnixPath,
    SessionProcessIdentityProof, SessionRuntimeEnvironmentProof, SESSION_CHILD_PROTOCOL_VERSION,
    SESSION_EXEC_PROBE_VERSION,
};
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        std::process::exit(1);
    }
    let username = args[1].clone();
    let session_id = args[2].clone();
    let audit = match LinuxPostDropAuditor.audit() {
        Ok(value) => value,
        Err(_) => std::process::exit(1),
    };
    let mut groups = vec![0 as libc::gid_t; 65536];
    let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    if count < 0 {
        std::process::exit(1);
    }
    groups.truncate(count as usize);
    let path = |name: &str| {
        std::env::var_os(name)
            .and_then(|p| SessionChildUnixPath::new(std::path::Path::new(&p)).ok())
    };
    let home = match path("HOME") {
        Some(v) => v,
        None => std::process::exit(1),
    };
    let shell = match path("SHELL") {
        Some(v) => v,
        None => std::process::exit(1),
    };
    let cwd = match std::env::current_dir()
        .ok()
        .and_then(|p| SessionChildUnixPath::new(&p).ok())
    {
        Some(v) => v,
        None => std::process::exit(1),
    };
    let pid = std::process::id();
    let sid = unsafe { libc::getsid(0) as u32 };
    let pgid = unsafe { libc::getpgid(0) as u32 };
    if sid != pid || pgid != pid {
        std::process::exit(1);
    }
    let response = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildResponse::Ready {
            canonical_username: username.clone(),
            session_id,
            child_pid: pid,
            applied_credentials: SessionChildUnixCredentials {
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
                supplementary_gids: groups.into_iter().map(|g| g as u32).collect(),
            },
            isolation_proof: SessionChildIsolationProof::from(&audit),
            process_identity: SessionProcessIdentityProof { pid, sid, pgid },
            runtime_environment: SessionRuntimeEnvironmentProof {
                home,
                user: username.clone(),
                logname: username,
                shell,
                path: std::env::var("PATH").unwrap_or_default(),
                session_type: std::env::var("XDG_SESSION_TYPE").unwrap_or_default(),
                cwd,
            },
            exec_probe_version: SESSION_EXEC_PROBE_VERSION,
        },
    };
    let mut out = std::io::stdout().lock();
    if serde_json::to_writer(&mut out, &response).is_err() || out.write_all(b"\n").is_err() {
        std::process::exit(1);
    }
}
