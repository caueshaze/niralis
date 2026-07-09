use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use niralis_protocol::{SessionInfo, SessionKind};
use tracing::{debug, warn};

use crate::sessions::desktop_entry::parse_desktop_session;
use crate::{DiscoveryError, SessionDiscoveryConfig};

pub(super) fn list_sessions(
    config: &SessionDiscoveryConfig,
) -> Result<Vec<SessionInfo>, DiscoveryError> {
    let mut sessions = Vec::new();

    for dir in &config.wayland_dirs {
        collect_from_dir(dir, SessionKind::Wayland, config, &mut sessions)?;
    }

    if config.include_x11 {
        for dir in &config.x11_dirs {
            collect_from_dir(dir, SessionKind::X11, config, &mut sessions)?;
        }
    }

    sessions.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(sessions)
}

fn collect_from_dir(
    dir: &Path,
    kind: SessionKind,
    config: &SessionDiscoveryConfig,
    sessions: &mut Vec<SessionInfo>,
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

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                debug!(%error, path = %dir.display(), "failed to read session directory entry");
                continue;
            }
        };

        let path = entry.path();
        if path.extension() != Some(OsStr::new("desktop")) {
            continue;
        }

        match parse_desktop_session(&path, kind, &config.exec_search_path) {
            Some(session) => sessions.push(session),
            None => warn!(path = %path.display(), "session desktop entry ignored"),
        }
    }

    Ok(())
}
