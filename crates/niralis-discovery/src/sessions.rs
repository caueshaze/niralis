use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use niralis_protocol::{SessionInfo, SessionKind};
use tracing::{debug, warn};
use which::which_in;

use crate::DiscoveryError;

pub trait SessionDirectory: Send + Sync {
    fn list_sessions(&self) -> Result<Vec<SessionInfo>, DiscoveryError>;
}

impl<T> SessionDirectory for Box<T>
where
    T: SessionDirectory + ?Sized,
{
    fn list_sessions(&self) -> Result<Vec<SessionInfo>, DiscoveryError> {
        (**self).list_sessions()
    }
}

#[derive(Debug, Clone)]
pub struct SessionDiscoveryConfig {
    pub wayland_dirs: Vec<PathBuf>,
    pub include_x11: bool,
    pub x11_dirs: Vec<PathBuf>,
    pub exec_search_path: Vec<PathBuf>,
}

impl Default for SessionDiscoveryConfig {
    fn default() -> Self {
        Self {
            wayland_dirs: vec![PathBuf::from("/usr/share/wayland-sessions")],
            include_x11: false,
            x11_dirs: vec![PathBuf::from("/usr/share/xsessions")],
            exec_search_path: vec![
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/usr/local/sbin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct DesktopSessionDirectory {
    config: SessionDiscoveryConfig,
}

impl DesktopSessionDirectory {
    pub fn new(config: SessionDiscoveryConfig) -> Self {
        Self { config }
    }
}

impl SessionDirectory for DesktopSessionDirectory {
    fn list_sessions(&self) -> Result<Vec<SessionInfo>, DiscoveryError> {
        let mut sessions = Vec::new();

        for dir in &self.config.wayland_dirs {
            self.collect_from_dir(dir, SessionKind::Wayland, &mut sessions)?;
        }

        if self.config.include_x11 {
            for dir in &self.config.x11_dirs {
                self.collect_from_dir(dir, SessionKind::X11, &mut sessions)?;
            }
        }

        sessions.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(sessions)
    }
}

impl DesktopSessionDirectory {
    fn collect_from_dir(
        &self,
        dir: &Path,
        kind: SessionKind,
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

            match parse_desktop_session(&path, kind, &self.config.exec_search_path) {
                Some(session) => sessions.push(session),
                None => warn!(path = %path.display(), "session desktop entry ignored"),
            }
        }

        Ok(())
    }
}

fn parse_desktop_session(
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

fn try_exec_is_available(value: &str, search_path: &[PathBuf]) -> bool {
    let candidate = Path::new(value);
    if candidate.is_absolute() {
        return is_executable(candidate);
    }

    if value.contains('/') {
        return false;
    }

    let joined = match std::env::join_paths(search_path) {
        Ok(paths) => paths,
        Err(_) => return false,
    };

    which_in(value, Some(joined), "/")
        .ok()
        .as_deref()
        .is_some_and(is_executable)
}

fn is_executable(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;

    fn write_file(path: &Path, content: &str) {
        fs::write(path, content).expect("fixture should be written");
    }

    fn make_executable(path: &Path) {
        write_file(path, "#!/bin/sh\n");
        let mut permissions = fs::metadata(path)
            .expect("fixture metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("fixture permissions should be set");
    }

    fn config_for(dir: &Path) -> SessionDiscoveryConfig {
        SessionDiscoveryConfig {
            wayland_dirs: vec![dir.to_path_buf()],
            include_x11: false,
            x11_dirs: Vec::new(),
            exec_search_path: Vec::new(),
        }
    }

    fn list(dir: &Path) -> Vec<SessionInfo> {
        DesktopSessionDirectory::new(config_for(dir))
            .list_sessions()
            .expect("session discovery should succeed")
    }

    #[test]
    fn includes_valid_wayland_session() {
        let temp = TempDir::new().expect("temp dir should be created");
        write_file(
            &temp.path().join("niri.desktop"),
            "[Desktop Entry]\nType=Application\nName=Niri\nExec=niri-session\n",
        );

        assert_eq!(
            list(temp.path()),
            vec![SessionInfo {
                id: "niri".to_owned(),
                name: "Niri".to_owned(),
                kind: SessionKind::Wayland,
            }]
        );
    }

    #[test]
    fn omits_missing_or_invalid_type() {
        let temp = TempDir::new().expect("temp dir should be created");
        write_file(
            &temp.path().join("missing.desktop"),
            "[Desktop Entry]\nName=A\nExec=a\n",
        );
        write_file(
            &temp.path().join("link.desktop"),
            "[Desktop Entry]\nType=Link\nName=B\nExec=b\n",
        );

        assert!(list(temp.path()).is_empty());
    }

    #[test]
    fn omits_missing_name_or_exec() {
        let temp = TempDir::new().expect("temp dir should be created");
        write_file(
            &temp.path().join("noname.desktop"),
            "[Desktop Entry]\nType=Application\nExec=a\n",
        );
        write_file(
            &temp.path().join("noexec.desktop"),
            "[Desktop Entry]\nType=Application\nName=A\n",
        );

        assert!(list(temp.path()).is_empty());
    }

    #[test]
    fn omits_hidden_or_no_display() {
        let temp = TempDir::new().expect("temp dir should be created");
        write_file(
            &temp.path().join("hidden.desktop"),
            "[Desktop Entry]\nType=Application\nName=A\nExec=a\nHidden=true\n",
        );
        write_file(
            &temp.path().join("nodisplay.desktop"),
            "[Desktop Entry]\nType=Application\nName=B\nExec=b\nNoDisplay=true\n",
        );

        assert!(list(temp.path()).is_empty());
    }

    #[test]
    fn try_exec_absolute_must_exist_and_be_executable() {
        let temp = TempDir::new().expect("temp dir should be created");
        let bin = temp.path().join("bin");
        make_executable(&bin);
        write_file(
            &temp.path().join("ok.desktop"),
            &format!(
                "[Desktop Entry]\nType=Application\nName=Ok\nExec=ok\nTryExec={}\n",
                bin.display()
            ),
        );
        write_file(
            &temp.path().join("missing.desktop"),
            "[Desktop Entry]\nType=Application\nName=Missing\nExec=missing\nTryExec=/does/not/exist\n",
        );

        let sessions = list(temp.path());
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "ok");
    }

    #[test]
    fn try_exec_absolute_non_executable_is_omitted() {
        let temp = TempDir::new().expect("temp dir should be created");
        let bin = temp.path().join("bin");
        write_file(&bin, "not executable\n");
        write_file(
            &temp.path().join("bad.desktop"),
            &format!(
                "[Desktop Entry]\nType=Application\nName=Bad\nExec=bad\nTryExec={}\n",
                bin.display()
            ),
        );

        assert!(list(temp.path()).is_empty());
    }

    #[test]
    fn try_exec_relative_uses_configured_search_path_only() {
        let temp = TempDir::new().expect("temp dir should be created");
        let bin_dir = temp.path().join("bin");
        fs::create_dir(&bin_dir).expect("bin dir should be created");
        make_executable(&bin_dir.join("niri"));
        write_file(
            &temp.path().join("niri.desktop"),
            "[Desktop Entry]\nType=Application\nName=Niri\nExec=niri\nTryExec=niri\n",
        );
        let mut config = config_for(temp.path());
        config.exec_search_path = vec![bin_dir];

        let sessions = DesktopSessionDirectory::new(config)
            .list_sessions()
            .expect("session discovery should succeed");

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "niri");
    }

    #[test]
    fn try_exec_relative_not_found_is_omitted() {
        let temp = TempDir::new().expect("temp dir should be created");
        write_file(
            &temp.path().join("niri.desktop"),
            "[Desktop Entry]\nType=Application\nName=Niri\nExec=niri\nTryExec=niri\n",
        );

        assert!(list(temp.path()).is_empty());
    }

    #[test]
    fn malformed_and_non_desktop_files_are_ignored() {
        let temp = TempDir::new().expect("temp dir should be created");
        write_file(
            &temp.path().join("bad.desktop"),
            "not an ini file\n=broken\n",
        );
        write_file(
            &temp.path().join("notes.txt"),
            "[Desktop Entry]\nType=Application\nName=A\nExec=a\n",
        );

        assert!(list(temp.path()).is_empty());
    }

    #[test]
    fn supports_x11_when_enabled() {
        let wayland = TempDir::new().expect("temp dir should be created");
        let x11 = TempDir::new().expect("temp dir should be created");
        write_file(
            &x11.path().join("plasma.desktop"),
            "[Desktop Entry]\nType=Application\nName=Plasma\nExec=startplasma-x11\n",
        );
        let config = SessionDiscoveryConfig {
            wayland_dirs: vec![wayland.path().to_path_buf()],
            include_x11: true,
            x11_dirs: vec![x11.path().to_path_buf()],
            exec_search_path: Vec::new(),
        };

        let sessions = DesktopSessionDirectory::new(config)
            .list_sessions()
            .expect("session discovery should succeed");

        assert_eq!(sessions[0].kind, SessionKind::X11);
    }

    #[test]
    fn sorts_deterministically() {
        let temp = TempDir::new().expect("temp dir should be created");
        write_file(
            &temp.path().join("z.desktop"),
            "[Desktop Entry]\nType=Application\nName=Zed\nExec=z\n",
        );
        write_file(
            &temp.path().join("b.desktop"),
            "[Desktop Entry]\nType=Application\nName=Alpha\nExec=b\n",
        );
        write_file(
            &temp.path().join("a.desktop"),
            "[Desktop Entry]\nType=Application\nName=Alpha\nExec=a\n",
        );

        let ids: Vec<String> = list(temp.path())
            .into_iter()
            .map(|session| session.id)
            .collect();
        assert_eq!(ids, vec!["a", "b", "z"]);
    }
}
