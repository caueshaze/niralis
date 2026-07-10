use niralis_session_worker::{
    LinuxPostDropAuditor, PostDropAuditor, SessionChildCredentialProof, SessionChildEnvelope,
    SessionChildIsolationProof, SessionChildResponse, SessionChildUnixCredentials,
    SessionChildUnixPath, SessionProcessIdentityProof, SessionRuntimeEnvironmentProof,
    SESSION_CHILD_PROTOCOL_VERSION, SESSION_EXEC_PROBE_VERSION,
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
    groups.sort_unstable();
    groups.dedup();
    let gid = unsafe { libc::getgid() as u32 };
    groups.retain(|group| *group as u32 != gid);
    let groups: Vec<u32> = groups.into_iter().map(|group| group as u32).collect();
    let (mut ruid, mut euid, mut suid) = (0, 0, 0);
    let (mut rgid, mut egid, mut sgid) = (0, 0, 0);
    if unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) } != 0
        || unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) } != 0
    {
        std::process::exit(1);
    }
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
                uid: ruid,
                gid: rgid,
                supplementary_gids: groups.clone(),
            },
            credential_proof: SessionChildCredentialProof {
                real_uid: ruid,
                effective_uid: euid,
                saved_uid: suid,
                real_gid: rgid,
                effective_gid: egid,
                saved_gid: sgid,
                supplementary_gids: groups,
            },
            isolation_proof: SessionChildIsolationProof::from(&audit),
            process_identity: SessionProcessIdentityProof { pid, sid, pgid },
            runtime_environment: SessionRuntimeEnvironmentProof {
                home,
                user: match std::env::var("USER") {
                    Ok(value) => value,
                    Err(_) => std::process::exit(1),
                },
                logname: match std::env::var("LOGNAME") {
                    Ok(value) => value,
                    Err(_) => std::process::exit(1),
                },
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
