use std::fs;

use niralis_protocol::{SessionInfo, SessionKind};

use super::fixtures::{config_for, list, make_executable, tempdir, write_file};
use crate::sessions::{
    DesktopSessionDirectory, SessionDirectory, SessionDiscoveryConfig, SessionSourceTrustPolicy,
};

#[test]
fn list_filters_and_sorts_wayland_entries() {
    let temp = tempdir();
    write_file(
        &temp.path().join("niri.desktop"),
        "[Desktop Entry]\nType=Application\nName=Niri\nExec=niri-session\n",
    );
    write_file(
        &temp.path().join("missing.desktop"),
        "[Desktop Entry]\nName=A\nExec=a\n",
    );
    write_file(
        &temp.path().join("link.desktop"),
        "[Desktop Entry]\nType=Link\nName=B\nExec=b\n",
    );
    write_file(
        &temp.path().join("hidden.desktop"),
        "[Desktop Entry]\nType=Application\nName=A\nExec=a\nHidden=true\n",
    );
    write_file(
        &temp.path().join("nodisplay.desktop"),
        "[Desktop Entry]\nType=Application\nName=B\nExec=b\nNoDisplay=true\n",
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
fn list_respects_try_exec_and_ignores_malformed_or_non_desktop() {
    let temp = tempdir();
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
        &temp.path().join("bad.desktop"),
        "not an ini file\n=broken\n",
    );
    write_file(
        &temp.path().join("missing.desktop"),
        "[Desktop Entry]\nType=Application\nName=Missing\nExec=missing\nTryExec=/does/not/exist\n",
    );
    write_file(
        &temp.path().join("notes.txt"),
        "[Desktop Entry]\nType=Application\nName=A\nExec=a\n",
    );

    let sessions = list(temp.path());
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].id, "ok");
}

#[test]
fn list_uses_relative_search_path_and_supports_x11_when_enabled() {
    let temp = tempdir();
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
    assert_eq!(sessions[0].id, "niri");

    let wayland = tempdir();
    let x11 = tempdir();
    write_file(
        &x11.path().join("plasma.desktop"),
        "[Desktop Entry]\nType=Application\nName=Plasma\nExec=startplasma-x11\n",
    );
    let config = SessionDiscoveryConfig {
        wayland_dirs: vec![wayland.path().to_path_buf()],
        include_x11: true,
        x11_dirs: vec![x11.path().to_path_buf()],
        exec_search_path: Vec::new(),
        source_trust: SessionSourceTrustPolicy::Permissive,
    };
    let sessions = DesktopSessionDirectory::new(config)
        .list_sessions()
        .expect("session discovery should succeed");
    assert_eq!(sessions[0].kind, SessionKind::X11);
}
