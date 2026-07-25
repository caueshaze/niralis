use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::Child;
use std::time::{Duration, Instant};

pub(super) fn fixture_helper_path() -> Result<std::path::PathBuf, String> {
    let path = std::env::var_os("NIRALIS_SYSTEMD_FIXTURE_HELPER")
        .map(std::path::PathBuf::from)
        .ok_or("fixture helper path is not set by the safe runner")?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| "fixture helper path is unavailable".to_owned())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err("fixture helper must be a regular executable, not a symlink".to_owned());
    }
    Ok(path)
}

pub(super) fn parse_ready(
    line: &str,
    expect_descendant: bool,
) -> Result<(u32, Option<u32>), String> {
    let mut values = line.split_ascii_whitespace();
    if values.next() != Some("READY") {
        return Err("fixture helper emitted an invalid barrier".to_owned());
    }
    let pid = values
        .next()
        .and_then(|value| value.strip_prefix("helper_pid="))
        .and_then(|value| value.parse().ok())
        .filter(|pid| *pid != 0)
        .ok_or("fixture helper Ready is missing its PID")?;
    let child = values
        .next()
        .and_then(|value| value.strip_prefix("descendant_pid="))
        .and_then(|value| value.parse().ok())
        .filter(|pid| *pid != 0);
    if values.next().is_some() || expect_descendant != child.is_some() || child == Some(pid) {
        return Err("fixture helper Ready has an invalid identity".to_owned());
    }
    Ok((pid, child))
}

pub(super) fn proc_starttime(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()?
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

pub(super) fn rand_token() -> Result<u128, String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut bytes))
        .map_err(|_| "cannot obtain 128 bits of fixture entropy".to_owned())?;
    Ok(u128::from_ne_bytes(bytes))
}

pub(super) fn fixture_expected_uid() -> Result<u32, String> {
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid != 0 {
        return Ok(effective_uid);
    }
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|uid| *uid != 0)
        .ok_or_else(|| {
            "root integration execution requires sudo to provide a non-root SUDO_UID".to_owned()
        })
}

pub(super) fn wait_for_fixture_ready(
    listener: &UnixListener,
    launcher: &mut Child,
) -> Result<String, String> {
    listener
        .set_nonblocking(true)
        .map_err(|_| "fixture Ready listener cannot become nonblocking".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut ready = String::new();
                BufReader::new(stream)
                    .read_line(&mut ready)
                    .map_err(|_| "fixture helper did not emit Ready".to_owned())?;
                return Ok(ready);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err("fixture helper Ready listener failed".to_owned()),
        }
        match launcher.try_wait() {
            Ok(Some(status)) => {
                return Err(format!("systemd-run exited before helper Ready: {status}"))
            }
            Ok(None) => {}
            Err(_) => return Err("cannot observe systemd-run before helper Ready".to_owned()),
        }
        if Instant::now() >= deadline {
            return Err("fixture helper Ready timed out".to_owned());
        }
        let mut descriptor = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut descriptor, 1, 50) } < 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
        {
            return Err("fixture Ready poll failed".to_owned());
        }
    }
}
