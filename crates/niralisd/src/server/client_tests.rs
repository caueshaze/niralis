
fn lookup_passwd(username: &CStr, buffer: &mut [libc::c_char]) -> NssLookupResult {
    // SAFETY: all pointers reference valid writable storage for the duration of
    // this reentrant NSS call. The passwd fields are copied before returning.
    unsafe {
        let mut passwd: libc::passwd = std::mem::zeroed();
        let mut result = std::ptr::null_mut();
        let status = libc::getpwnam_r(
            username.as_ptr(),
            &mut passwd,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        );

        if status == libc::ERANGE {
            return NssLookupResult::Retry;
        }
        if status != 0 {
            return NssLookupResult::Error(io::Error::from_raw_os_error(status));
        }
        if result.is_null() {
            return NssLookupResult::NotFound;
        }

        let canonical_name = CStr::from_ptr(passwd.pw_name)
            .to_string_lossy()
            .into_owned();
        NssLookupResult::Found(GreeterIdentity {
            username: canonical_name,
            uid: passwd.pw_uid,
            gid: passwd.pw_gid,
        })
    }
}

fn handle_client<H>(stream: UnixStream, handler: &H) -> Result<()>
where
    H: RequestHandler,
{
    let writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut line = Zeroizing::new(String::new());

    reader.read_line(&mut *line)?;
    debug!("received ipc request");

    let response = if line.trim().is_empty() {
        NiralisResponse::Error {
            message: "empty request".to_owned(),
        }
    } else {
        let request: NiralisRequest = serde_json::from_str(line.trim_end())?;
        (*line).zeroize();
        handler.handle(request)
    };

    write_response(writer, &response)?;

    Ok(())
}

fn write_response(mut writer: UnixStream, response: &NiralisResponse) -> Result<()> {
    serde_json::to_writer(&mut writer, response)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn identity(uid: libc::uid_t, gid: libc::gid_t) -> GreeterIdentity {
        GreeterIdentity {
            username: "canonical-greeter".to_owned(),
            uid,
            gid,
        }
    }

    #[test]
    fn valid_greeter_resolves_to_the_identity_returned_by_nss() {
        let resolved = resolve_greeter_identity_with("configured-greeter", |_, _| {
            NssLookupResult::Found(identity(464, 465))
        })
        .unwrap();

        assert_eq!(resolved, identity(464, 465));
    }

    #[test]
    fn nonexistent_greeter_fails_closed() {
        let error =
            resolve_greeter_identity_with("missing", |_, _| NssLookupResult::NotFound).unwrap_err();

        assert!(matches!(error, NiralisdError::GreeterUserNotFound(name) if name == "missing"));
    }

    #[test]
    fn root_uid_is_rejected() {
        let error = resolve_greeter_identity_with("greeter", |_, _| {
            NssLookupResult::Found(identity(0, 464))
        })
        .unwrap_err();

        assert!(matches!(error, NiralisdError::InvalidGreeterUid));
    }

    #[test]
    fn root_primary_gid_is_rejected() {
        let error = resolve_greeter_identity_with("greeter", |_, _| {
            NssLookupResult::Found(identity(464, 0))
        })
        .unwrap_err();

        assert!(matches!(error, NiralisdError::InvalidGreeterGid));
    }

    #[test]
    fn nul_in_greeter_name_is_rejected_without_nss_lookup() {
        let error = resolve_greeter_identity_with("greeter\0injected", |_, _| {
            panic!("NSS lookup must not receive a name containing NUL")
        })
        .unwrap_err();

        assert!(matches!(error, NiralisdError::GreeterUserNameContainsNul));
    }

    #[test]
    fn nss_lookup_error_is_propagated() {
        let error = resolve_greeter_identity_with("greeter", |_, _| {
            NssLookupResult::Error(io::Error::from_raw_os_error(libc::EIO))
        })
        .unwrap_err();

        assert!(matches!(
            error,
            NiralisdError::GreeterIdentityLookupFailed { source, .. }
                if source.raw_os_error() == Some(libc::EIO)
        ));
    }

    #[test]
    fn erange_retries_with_a_larger_buffer() {
        let calls = RefCell::new(0);
        let resolved = resolve_greeter_identity_with("greeter", |_, buffer| {
            let mut calls = calls.borrow_mut();
            *calls += 1;
            if *calls == 1 {
                assert!(buffer.len() < NSS_BUFFER_MAX);
                NssLookupResult::Retry
            } else {
                NssLookupResult::Found(identity(464, 465))
            }
        })
        .unwrap();

        assert_eq!(resolved.gid, 465);
        assert_eq!(*calls.borrow(), 2);
    }

    #[test]
    fn socket_uses_greeter_primary_gid_and_mode_0660() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("niralisd.sock");
        let ownership = RefCell::new(None);
        let greeter = identity(464, 465);

        let listener = bind_socket_with(&socket_path, &greeter, |_, uid, gid| {
            *ownership.borrow_mut() = Some((uid, gid));
            Ok(())
        })
        .unwrap();

        let mode = fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        assert_eq!(*ownership.borrow(), Some((0, 465)));
        drop(listener);
    }

    #[test]
    fn ownership_failure_returns_no_listener_and_removes_socket() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("niralisd.sock");

        let error = bind_socket_with(&socket_path, &identity(464, 465), |_, _, _| {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })
        .unwrap_err();

        assert!(
            matches!(error, NiralisdError::Io(source) if source.raw_os_error() == Some(libc::EPERM))
        );
        assert!(!socket_path.exists());
    }
}
