use std::path::PathBuf;

use niralis_protocol::{SessionInfo, SessionKind};

use super::fixtures::{find, tempdir, write_file};
use crate::sessions::{DesktopSessionDirectory, SessionDirectory, SessionDiscoveryConfig};
use crate::DiscoveryError;

#[test]
fn find_matches_exact_id_only() {
    let temp = tempdir();
    write_file(
        &temp.path().join("niri.desktop"),
        "[Desktop Entry]\nType=Application\nName=Niri\nExec=niri-session\n",
    );

    assert_eq!(find(temp.path(), "missing"), None);
    assert_eq!(find(temp.path(), "nir"), None);
    assert_eq!(find(temp.path(), "niri-session"), None);
    assert_eq!(
        find(temp.path(), "niri"),
        Some(SessionInfo {
            id: "niri".to_owned(),
            name: "Niri".to_owned(),
            kind: SessionKind::Wayland,
        })
    );
}

#[test]
fn find_rejects_ineligible_entries() {
    let temp = tempdir();
    write_file(
        &temp.path().join("hidden.desktop"),
        "[Desktop Entry]\nType=Application\nName=Niri\nExec=niri-session\nHidden=true\n",
    );
    write_file(
        &temp.path().join("nodisplay.desktop"),
        "[Desktop Entry]\nType=Application\nName=Niri\nExec=niri-session\nNoDisplay=true\n",
    );
    write_file(
        &temp.path().join("tryexec.desktop"),
        "[Desktop Entry]\nType=Application\nName=Niri\nExec=niri-session\nTryExec=/does/not/exist\n",
    );

    assert_eq!(find(temp.path(), "hidden"), None);
    assert_eq!(find(temp.path(), "nodisplay"), None);
    assert_eq!(find(temp.path(), "tryexec"), None);
}

#[test]
fn find_handles_x11_flag_and_discovery_errors() {
    let wayland = tempdir();
    let x11 = tempdir();
    write_file(
        &x11.path().join("plasma.desktop"),
        "[Desktop Entry]\nType=Application\nName=Plasma\nExec=startplasma-x11\n",
    );

    let disabled = SessionDiscoveryConfig {
        wayland_dirs: vec![wayland.path().to_path_buf()],
        include_x11: false,
        x11_dirs: vec![x11.path().to_path_buf()],
        exec_search_path: Vec::new(),
    };
    assert_eq!(
        DesktopSessionDirectory::new(disabled)
            .find_session("plasma")
            .expect("session discovery should succeed"),
        None
    );

    let enabled = SessionDiscoveryConfig {
        wayland_dirs: vec![wayland.path().to_path_buf()],
        include_x11: true,
        x11_dirs: vec![x11.path().to_path_buf()],
        exec_search_path: Vec::new(),
    };
    assert_eq!(
        DesktopSessionDirectory::new(enabled)
            .find_session("plasma")
            .expect("session discovery should succeed"),
        Some(SessionInfo {
            id: "plasma".to_owned(),
            name: "Plasma".to_owned(),
            kind: SessionKind::X11,
        })
    );

    let error = DesktopSessionDirectory::new(SessionDiscoveryConfig {
        wayland_dirs: vec![PathBuf::from("/proc/1/fd/0")],
        include_x11: false,
        x11_dirs: Vec::new(),
        exec_search_path: Vec::new(),
    })
    .find_session("niri")
    .expect_err("non-directory should fail");
    assert!(matches!(error, DiscoveryError::ReadDir { .. }));
}
