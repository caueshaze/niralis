use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use which::which_in;

pub(super) fn try_exec_is_available(value: &str, search_path: &[PathBuf]) -> bool {
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
