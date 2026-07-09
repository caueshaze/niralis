use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use niralis_protocol::{SessionInfo, SessionKind};
use tracing::{debug, warn};

use crate::sessions::exec_check::try_exec_is_available;
use crate::DiscoveryError;

pub(super) fn parse_desktop_session(
    path: &Path,
    kind: SessionKind,
    exec_search_path: &[PathBuf],
) -> Option<SessionInfo> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) => {
            warn!(
                error = %DiscoveryError::ReadDesktopEntry {
                    path: path.to_path_buf(),
                    source: error,
                },
                path = %path.display(),
                "failed to read session desktop file"
            );
            return None;
        }
    };

    let fields = desktop_entry_fields(&raw);
    if fields.get("Type").map(String::as_str) != Some("Application") {
        return None;
    }
    if bool_field(&fields, "Hidden") || bool_field(&fields, "NoDisplay") {
        return None;
    }

    let name = required_field(&fields, "Name")?;
    let _exec = required_field(&fields, "Exec")?;

    if let Some(try_exec) = fields.get("TryExec").map(String::as_str).map(str::trim) {
        if !try_exec.is_empty() && !try_exec_is_available(try_exec, exec_search_path) {
            return None;
        }
    }

    let id = path.file_stem()?.to_string_lossy().into_owned();
    if id.is_empty() {
        return None;
    }

    Some(SessionInfo { id, name, kind })
}

fn desktop_entry_fields(raw: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let mut in_desktop_entry = false;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_desktop_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_desktop_entry {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            debug!("malformed desktop entry line ignored");
            continue;
        };
        fields.insert(key.trim().to_owned(), value.trim().to_owned());
    }

    fields
}

fn required_field(fields: &HashMap<String, String>, key: &str) -> Option<String> {
    let value = fields.get(key)?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn bool_field(fields: &HashMap<String, String>, key: &str) -> bool {
    fields
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}
