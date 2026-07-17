#[cfg(test)]
mod terminal_binding_tests {
    use super::*;

    fn identity() -> LogindSessionIdentity {
        LogindSessionIdentity {
            id: crate::LogindSessionId::new("c1".to_owned()).unwrap(),
            uid: 1000,
            session_type: "wayland".to_owned(),
            class: "user".to_owned(),
            desktop: Some("niri".to_owned()),
            seat: Some("seat0".to_owned()),
            vtnr: Some(2),
        }
    }

    #[test]
    fn logind_seat_and_vt_are_bound_to_the_owned_terminal() {
        let identity = identity();
        assert!(valid_logind_identity(
            &identity, 1000, "wayland", "niri", "seat0", 2
        ));
        assert!(!valid_logind_identity(
            &identity, 1000, "wayland", "niri", "seat1", 2
        ));
        assert!(!valid_logind_identity(
            &identity, 1000, "wayland", "niri", "seat0", 3
        ));
    }
}

fn write_rejection<W: Write>(writer: &mut W, code: WorkerErrorCode) -> Result<(), SessionError> {
    write_envelope(writer, WorkerResponse::Rejected { code })
}

#[cfg(test)]
mod runtime_dir_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("niralis-4gc-{name}-{}", std::process::id()))
    }

    #[test]
    fn validates_existing_owned_mode_0700_directory() {
        let directory = path("valid");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(LinuxRuntimeDirValidator.validate(&directory, uid).is_ok());
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn rejects_relative_and_symlink_runtime_paths() {
        let directory = path("target");
        let link = path("link");
        let _ = std::fs::remove_dir_all(&directory);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir(&directory).unwrap();
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            LinuxRuntimeDirValidator.validate(Path::new("relative"), uid),
            Err(RuntimeDirValidationError::InvalidPath)
        );
        assert_eq!(
            LinuxRuntimeDirValidator.validate(&link, uid),
            Err(RuntimeDirValidationError::InvalidMetadata)
        );
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
