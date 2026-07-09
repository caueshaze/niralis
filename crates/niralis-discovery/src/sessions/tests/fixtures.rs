use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::TempDir;

use crate::sessions::{DesktopSessionDirectory, SessionDirectory, SessionDiscoveryConfig};

pub(super) fn write_file(path: &Path, content: &str) {
    fs::write(path, content).expect("fixture should be written");
}

pub(super) fn make_executable(path: &Path) {
    write_file(path, "#!/bin/sh\n");
    let mut permissions = fs::metadata(path)
        .expect("fixture metadata should exist")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("fixture permissions should be set");
}

pub(super) fn config_for(dir: &Path) -> SessionDiscoveryConfig {
    SessionDiscoveryConfig {
        wayland_dirs: vec![dir.to_path_buf()],
        include_x11: false,
        x11_dirs: Vec::new(),
        exec_search_path: Vec::new(),
    }
}

pub(super) fn list(dir: &Path) -> Vec<niralis_protocol::SessionInfo> {
    DesktopSessionDirectory::new(config_for(dir))
        .list_sessions()
        .expect("session discovery should succeed")
}

pub(super) fn find(dir: &Path, id: &str) -> Option<niralis_protocol::SessionInfo> {
    DesktopSessionDirectory::new(config_for(dir))
        .find_session(id)
        .expect("session discovery should succeed")
}

pub(super) fn tempdir() -> TempDir {
    TempDir::new().expect("temp dir should be created")
}
