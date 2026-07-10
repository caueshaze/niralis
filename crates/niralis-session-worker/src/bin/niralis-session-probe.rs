use niralis_session_worker::{
    LinuxPostDropAuditor, PostDropAuditor, SessionChildCredentialProof, SessionChildEnvelope,
    SessionChildIsolationProof, SessionChildResponse, SessionChildTerminalProof,
    SessionChildUnixCredentials, SessionChildUnixPath, SessionProcessIdentityProof,
    SessionRuntimeEnvironmentProof, SESSION_CHILD_PROTOCOL_VERSION, SESSION_EXEC_PROBE_VERSION,
};
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 && args.len() != 11 {
        std::process::exit(1);
    }
    let username = args[1].clone();
    let session_id = args[2].clone();
    let terminal_args = if args.len() == 11
        && args[3] == "--terminal-seat"
        && args[5] == "--terminal-vtnr"
        && args[7] == "--terminal-major"
        && args[9] == "--terminal-minor"
    {
        Some((
            args[4].clone(),
            args[6].parse::<u32>().ok(),
            args[8].parse::<u32>().ok(),
            args[10].parse::<u32>().ok(),
        ))
    } else {
        None
    };
    let terminal_proof = terminal_args.and_then(|(seat, vtnr, major, minor)| {
        let (Some(vtnr), Some(major), Some(minor)) = (vtnr, major, minor) else {
            return None;
        };
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        let fd_number = std::os::fd::AsRawFd::as_raw_fd(&fd);
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(fd_number, &mut stat) } < 0
            || libc::major(stat.st_rdev) as u32 != major
            || libc::minor(stat.st_rdev) as u32 != minor
        {
            return None;
        }
        let sid = unsafe { libc::tcgetsid(fd_number) };
        let pgid = unsafe { libc::tcgetpgrp(fd_number) };
        let pid = std::process::id();
        if sid <= 0 || pgid <= 0 || sid as u32 != pid || pgid as u32 != pid {
            return None;
        }
        Some(SessionChildTerminalProof {
            seat,
            vtnr,
            fd: 3,
            device_major: major,
            device_minor: minor,
            controlling_sid: sid as u32,
            foreground_pgid: pgid as u32,
        })
    });
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
    let forbidden_names = [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "GCONV_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "PERL5LIB",
        "PERLLIB",
        "RUBYLIB",
        "RUBYOPT",
        "NODE_OPTIONS",
        "BASH_ENV",
        "ENV",
        "GIO_EXTRA_MODULES",
        "GIO_MODULE_DIR",
        "GTK_PATH",
        "GTK_IM_MODULE_FILE",
        "QT_PLUGIN_PATH",
        "QT_QPA_PLATFORM_PLUGIN_PATH",
        "WAYLAND_DISPLAY",
        "DISPLAY",
        "XAUTHORITY",
    ];
    let forbidden_variables_present: Vec<String> = forbidden_names
        .iter()
        .filter(|name| std::env::var_os(name).is_some())
        .map(|name| (*name).to_owned())
        .collect();
    if !forbidden_variables_present.is_empty() {
        std::process::exit(1);
    }
    let imported_locale = std::env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.to_str()?.to_owned();
            if key == "LANG" || key == "LANGUAGE" || key.starts_with("LC_") {
                Some((key, value.to_str()?.to_owned()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if niralis_session_worker::prove_user_bus().is_err() {
        std::process::exit(1);
    }
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
                session_class: std::env::var("XDG_SESSION_CLASS").unwrap_or_default(),
                session_desktop: std::env::var("XDG_SESSION_DESKTOP").unwrap_or_default(),
                session_id: std::env::var("XDG_SESSION_ID").unwrap_or_default(),
                runtime_dir: path("XDG_RUNTIME_DIR").unwrap_or_else(|| std::process::exit(1)),
                seat: std::env::var("XDG_SEAT").unwrap_or_default(),
                vtnr: std::env::var("XDG_VTNR")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                dbus_session_bus_address: std::env::var("DBUS_SESSION_BUS_ADDRESS").ok(),
                imported_locale,
                forbidden_variables_present,
                user_bus_connected: true,
                cwd,
                exec_plan: niralis_session::SessionExecPlan {
                    source_path: b"/legacy-probe.desktop".to_vec(),
                    executable: b"/bin/true".to_vec(),
                    argv: vec![b"true".to_vec()],
                },
            },
            exec_probe_version: SESSION_EXEC_PROBE_VERSION,
            terminal_proof,
        },
    };
    let mut out = std::io::stdout().lock();
    if serde_json::to_writer(&mut out, &response).is_err() || out.write_all(b"\n").is_err() {
        std::process::exit(1);
    }
    let _ = out.flush();
    std::thread::sleep(std::time::Duration::from_secs(60));
}
