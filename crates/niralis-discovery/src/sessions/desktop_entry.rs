use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use niralis_protocol::{SessionInfo, SessionKind};
use tracing::debug;

use crate::sessions::trust::validate_source;
use crate::sessions::SessionDiscoveryConfig;
use crate::DiscoveryError;

#[derive(Debug, Clone)]
pub(super) struct CanonicalSessionEntry {
    pub session: SessionInfo,
    pub source_path: PathBuf,
    pub exec: String,
    pub try_exec: Option<String>,
}

pub(super) fn parse_desktop_session(
    path: &Path,
    kind: SessionKind,
    config: &SessionDiscoveryConfig,
) -> Result<Option<CanonicalSessionEntry>, DiscoveryError> {
    validate_source(path, config.source_trust, &session_root(config, kind, path))?;
    let metadata = fs::metadata(path).map_err(|source| DiscoveryError::ReadDesktopEntry {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > super::launch::MAX_DESKTOP_ENTRY_BYTES as u64 {
        return Err(DiscoveryError::InvalidLaunchSpec);
    }
    let bytes = fs::read(path).map_err(|source| DiscoveryError::ReadDesktopEntry {
        path: path.to_path_buf(),
        source,
    })?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| DiscoveryError::MalformedDesktopEntry {
        path: path.to_path_buf(),
    })?;

    let fields =
        desktop_entry_fields(raw).ok_or_else(|| DiscoveryError::MalformedDesktopEntry {
            path: path.to_path_buf(),
        })?;
    if fields.get("Type").map(String::as_str) != Some("Application") {
        return Ok(None);
    }
    if bool_field(&fields, "Hidden") || bool_field(&fields, "NoDisplay") {
        return Ok(None);
    }

    let Some(name) = required_field(&fields, "Name") else {
        return Ok(None);
    };
    let Some(exec) = required_field(&fields, "Exec") else {
        return Ok(None);
    };

    let Some(id) = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(str::to_owned)
    else {
        return Ok(None);
    };
    if id.is_empty() {
        return Ok(None);
    }

    Ok(Some(CanonicalSessionEntry {
        session: SessionInfo { id, name, kind },
        source_path: fs::canonicalize(path).map_err(|source| DiscoveryError::ReadDesktopEntry {
            path: path.to_path_buf(),
            source,
        })?,
        exec,
        try_exec: fields
            .get("TryExec")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
    }))
}

fn desktop_entry_fields(raw: &str) -> Option<std::collections::HashMap<String, String>> {
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
            return None;
        };
        let key = key.trim();
        if key.is_empty() {
            return None;
        }
        fields.insert(key.to_owned(), decode_value(value.trim())?);
    }

    Some(fields)
}

fn decode_value(value: &str) -> Option<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let next = match chars.next()? {
            's' => ' ',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            other @ ('"' | '$' | '`') => {
                decoded.push('\\');
                other
            }
            _ => return None,
        };
        decoded.push(next);
    }
    Some(decoded)
}

fn session_root(config: &SessionDiscoveryConfig, kind: SessionKind, path: &Path) -> PathBuf {
    let roots = match kind {
        SessionKind::Wayland => &config.wayland_dirs,
        SessionKind::X11 => &config.x11_dirs,
    };
    roots
        .iter()
        .find(|root| path.starts_with(root))
        .cloned()
        .unwrap_or_else(|| path.to_path_buf())
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
