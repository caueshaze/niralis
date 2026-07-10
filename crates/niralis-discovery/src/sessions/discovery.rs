use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use niralis_protocol::{SessionInfo, SessionKind};
use tracing::{debug, warn};

use crate::sessions::desktop_entry::{parse_desktop_session, CanonicalSessionEntry};
use crate::sessions::launch::try_exec_is_eligible;
use crate::{DiscoveryError, SessionDiscoveryConfig};

pub(super) fn list_sessions(
    config: &SessionDiscoveryConfig,
) -> Result<Vec<SessionInfo>, DiscoveryError> {
    let mut entries = collect_entries(config)?;
    let mut sessions: Vec<_> = entries.drain(..).map(|entry| entry.session).collect();

    sessions.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(sessions)
}

pub(super) fn find_entry(
    config: &SessionDiscoveryConfig,
    id: &str,
) -> Result<Option<CanonicalSessionEntry>, DiscoveryError> {
    Ok(collect_entries(config)?
        .into_iter()
        .find(|entry| entry.session.id == id))
}

fn collect_entries(
    config: &SessionDiscoveryConfig,
) -> Result<Vec<CanonicalSessionEntry>, DiscoveryError> {
    let mut entries = Vec::new();
    for dir in &config.wayland_dirs {
        collect_from_dir(dir, SessionKind::Wayland, config, &mut entries)?;
    }
    if config.include_x11 {
        for dir in &config.x11_dirs {
            collect_from_dir(dir, SessionKind::X11, config, &mut entries)?;
        }
    }
    let mut seen = std::collections::HashSet::new();
    entries.retain(|entry| seen.insert(entry.session.id.clone()));
    Ok(entries)
}

fn collect_from_dir(
    dir: &Path,
    kind: SessionKind,
    config: &SessionDiscoveryConfig,
    sessions: &mut Vec<CanonicalSessionEntry>,
) -> Result<(), DiscoveryError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = %dir.display(), "session directory does not exist");
            return Ok(());
        }
        Err(source) => {
            return Err(DiscoveryError::ReadDir {
                path: dir.to_path_buf(),
                source,
            });
        }
    };

    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.extension() != Some(OsStr::new("desktop")) {
            continue;
        }

        match parse_desktop_session(&path, kind, config) {
            Ok(Some(session)) if try_exec_is_eligible(&session, &config.exec_search_path) => {
                sessions.push(session)
            }
            Ok(Some(_)) => {
                warn!(path = %path.display(), "session desktop entry TryExec is unavailable")
            }
            Ok(None) => warn!(path = %path.display(), "session desktop entry ignored"),
            Err(error) => {
                warn!(path = %path.display(), error = %error, "session desktop entry ignored")
            }
        }
    }

    Ok(())
}
