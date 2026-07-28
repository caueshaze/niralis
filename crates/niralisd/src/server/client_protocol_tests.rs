#[cfg(test)]
mod tests {
    use niralis_protocol::{NiralisResponse, RequestId};
    use std::cell::RefCell;
    use std::io::{self, BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::sync::{atomic::{AtomicUsize, Ordering}, Arc, Barrier};
    use std::thread;
    use super::*;

    fn identity(uid: libc::uid_t, gid: libc::gid_t) -> GreeterIdentity {
        GreeterIdentity { username: "canonical-greeter".to_owned(), uid, gid }
    }

    struct ConcurrentHandler(Arc<AtomicUsize>);
    impl RequestHandler for ConcurrentHandler {
        fn handle(&self, _request: NiralisRequest) -> NiralisResponse {
            self.0.fetch_add(1, Ordering::SeqCst);
            NiralisResponse::Error { message: "ok".to_owned() }
        }
    }

    #[test]
    #[ignore = "requires host SO_PEERCRED support for UnixStream::pair"]
    fn two_authenticated_connections_with_barriers_20_of_20_without_sleep() {
        for _ in 0..20 {
            let calls = Arc::new(AtomicUsize::new(0));
            let handler = Arc::new(ConcurrentHandler(Arc::clone(&calls)));
            let barrier = Arc::new(Barrier::new(2));
            let expected = identity(unsafe { libc::getuid() }, unsafe { libc::getgid() });
            let mut clients = Vec::new();
            let mut servers = Vec::new();
            for _ in 0..2 {
                let (server, client) = UnixStream::pair().unwrap();
                let server_handler = Arc::clone(&handler);
                let server_expected = expected.clone();
                servers.push(thread::spawn(move || {
                    handle_client(server, server_handler.as_ref(), &server_expected, "seat0")
                        .expect("connection should complete");
                }));
                let client_barrier = Arc::clone(&barrier);
                clients.push(thread::spawn(move || {
                    let mut reader = BufReader::new(client.try_clone().unwrap());
                    let mut writer = client;
                    write_json_line(&mut writer, &GreeterHandshake {
                        protocol_version: GREETER_PROTOCOL_VERSION,
                        message_type: "handshake".to_owned(),
                    }).unwrap();
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let hello: GreeterHandshakeResponse = serde_json::from_str(line.trim()).unwrap();
                    let payload = GreeterRequest::Status;
                    let envelope = GreeterRequestEnvelope {
                        protocol_version: GREETER_PROTOCOL_VERSION,
                        message_type: "status".to_owned(),
                        connection_id: hello.connection_id,
                        connection_epoch: hello.connection_epoch,
                        request_id: RequestId(1), sequence: 1, seat: hello.seat,
                        payload_len: serde_json::to_vec(&payload).unwrap().len(), payload,
                    };
                    client_barrier.wait();
                    write_json_line(&mut writer, &envelope).unwrap();
                    line.clear(); reader.read_line(&mut line).unwrap();
                    let _: GreeterResponseEnvelope = serde_json::from_str(line.trim()).unwrap();
                }));
            }
            for client in clients { client.join().unwrap(); }
            for server in servers { server.join().unwrap(); }
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn valid_greeter_resolves_to_the_identity_returned_by_nss() {
        let resolved = resolve_greeter_identity_with("configured-greeter", |_, _| {
            NssLookupResult::Found(identity(464, 465))
        }).unwrap();
        assert_eq!(resolved, identity(464, 465));
    }

    #[test]
    fn nonexistent_greeter_fails_closed() {
        let error = resolve_greeter_identity_with("missing", |_, _| NssLookupResult::NotFound).unwrap_err();
        assert!(matches!(error, NiralisdError::GreeterUserNotFound(name) if name == "missing"));
    }

    #[test]
    fn root_uid_is_rejected() {
        let error = resolve_greeter_identity_with("greeter", |_, _| NssLookupResult::Found(identity(0, 464))).unwrap_err();
        assert!(matches!(error, NiralisdError::InvalidGreeterUid));
    }

    #[test]
    fn root_primary_gid_is_rejected() {
        let error = resolve_greeter_identity_with("greeter", |_, _| NssLookupResult::Found(identity(464, 0))).unwrap_err();
        assert!(matches!(error, NiralisdError::InvalidGreeterGid));
    }

    #[test]
    fn nul_in_greeter_name_is_rejected_without_nss_lookup() {
        let error = resolve_greeter_identity_with("greeter\0injected", |_, _| panic!("NSS lookup must not receive a name containing NUL")).unwrap_err();
        assert!(matches!(error, NiralisdError::GreeterUserNameContainsNul));
    }

    #[test]
    fn nss_lookup_error_is_propagated() {
        let error = resolve_greeter_identity_with("greeter", |_, _| NssLookupResult::Error(io::Error::from_raw_os_error(libc::EIO))).unwrap_err();
        assert!(matches!(error, NiralisdError::GreeterIdentityLookupFailed { source, .. } if source.raw_os_error() == Some(libc::EIO)));
    }

    #[test]
    fn erange_retries_with_a_larger_buffer() {
        let calls = RefCell::new(0);
        let resolved = resolve_greeter_identity_with("greeter", |_, buffer| {
            let mut calls = calls.borrow_mut(); *calls += 1;
            if *calls == 1 { assert!(buffer.len() < NSS_BUFFER_MAX); NssLookupResult::Retry }
            else { NssLookupResult::Found(identity(464, 465)) }
        }).unwrap();
        assert_eq!(resolved.gid, 465); assert_eq!(*calls.borrow(), 2);
    }

    #[test]
    fn socket_uses_greeter_primary_gid_and_mode_0660() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("niralisd.sock");
        let ownership = RefCell::new(None); let greeter = identity(464, 465);
        let listener = match bind_socket_with(&socket_path, &greeter, |_, uid, gid| {
            *ownership.borrow_mut() = Some((uid, gid)); Ok(())
        }) {
            Ok(listener) => listener,
            Err(NiralisdError::Io(error)) if error.raw_os_error() == Some(libc::EPERM) => return,
            Err(error) => panic!("socket configuration should succeed: {error}"),
        };
        let mode = fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660); assert_eq!(*ownership.borrow(), Some((0, 465))); drop(listener);
    }

    #[test]
    fn ownership_failure_returns_no_listener_and_removes_socket() {
        let tempdir = tempfile::tempdir().unwrap(); let socket_path = tempdir.path().join("niralisd.sock");
        let error = bind_socket_with(&socket_path, &identity(464, 465), |_, _, _| Err(io::Error::from_raw_os_error(libc::EPERM))).unwrap_err();
        assert!(matches!(error, NiralisdError::Io(source) if source.raw_os_error() == Some(libc::EPERM)));
        assert!(!socket_path.exists());
    }
}
