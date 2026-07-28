#[cfg(test)]
mod matrix_tests {
    use niralis_protocol::{NiralisResponse, RequestId};
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;
    use std::sync::{atomic::{AtomicUsize, Ordering}, Arc, Barrier};
    use std::thread;
    use super::*;

    fn identity(uid: libc::uid_t, gid: libc::gid_t) -> GreeterIdentity {
        GreeterIdentity { username: "canonical-greeter".to_owned(), uid, gid }
    }

    struct MatrixHandler(Arc<AtomicUsize>);
    impl RequestHandler for MatrixHandler {
        fn handle(&self, _request: NiralisRequest) -> NiralisResponse {
            self.0.fetch_add(1, Ordering::SeqCst);
            NiralisResponse::Error { message: "ok".to_owned() }
        }
    }
    fn handshake_client(mut stream: UnixStream) -> (UnixStream, GreeterHandshakeResponse) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        write_json_line(&mut stream, &GreeterHandshake {
            protocol_version: GREETER_PROTOCOL_VERSION,
            message_type: "handshake".to_owned(),
        }).unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        (stream, serde_json::from_str(line.trim()).unwrap())
    }

    fn envelope(
        hello: &GreeterHandshakeResponse,
        request_id: u64,
        sequence: u64,
        payload: GreeterRequest,
    ) -> GreeterRequestEnvelope {
        let message_type = match &payload {
            GreeterRequest::Status => "status",
            GreeterRequest::GetUsers => "get_users",
            GreeterRequest::GetSessions => "get_sessions",
            GreeterRequest::Login { .. } => "login",
            GreeterRequest::Cancel { .. } => "cancel",
        };
        GreeterRequestEnvelope {
            protocol_version: GREETER_PROTOCOL_VERSION,
            message_type: message_type.to_owned(),
            connection_id: hello.connection_id.clone(),
            connection_epoch: hello.connection_epoch,
            request_id: RequestId(request_id),
            sequence,
            seat: hello.seat.clone(),
            payload_len: serde_json::to_vec(&payload).unwrap().len(),
            payload,
        }
    }

    fn send_envelope(
        mut stream: UnixStream,
        request: GreeterRequestEnvelope,
        barrier: Option<Arc<Barrier>>,
    ) -> (UnixStream, GreeterResponseEnvelope) {
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        write_json_line(&mut stream, &request).unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        (stream, serde_json::from_str(line.trim()).unwrap())
    }

    #[test]
    #[ignore = "requires host SO_PEERCRED support for UnixStream::pair"]
    fn two_connections_login_disconnect_cancel_reconnect_20_of_20_without_sleep() {
        for _ in 0..20 {
            let calls = Arc::new(AtomicUsize::new(0));
            let handler = Arc::new(MatrixHandler(Arc::clone(&calls)));
            let expected = identity(unsafe { libc::getuid() }, unsafe { libc::getgid() });
            let (server_a, client_a) = UnixStream::pair().unwrap();
            let (server_b, client_b) = UnixStream::pair().unwrap();
            let handler_a = Arc::clone(&handler);
            let handler_b = Arc::clone(&handler);
            let expected_a = expected.clone();
            let expected_b = expected.clone();
            let server_a_thread = thread::spawn(move || {
                handle_client(server_a, handler_a.as_ref(), &expected_a, "seat0")
            });
            let server_b_thread = thread::spawn(move || {
                handle_client(server_b, handler_b.as_ref(), &expected_b, "seat0")
            });
            let (client_a, hello_a) = handshake_client(client_a);
            let (client_b, hello_b) = handshake_client(client_b);
            let stale = envelope(&hello_a, 9, 1, GreeterRequest::Status);
            let login = envelope(
                &hello_a,
                1,
                1,
                GreeterRequest::Login {
                    username: "test".to_owned(),
                    session: "niri".to_owned(),
                    secret: niralis_protocol::LoginSecret::new("not-for-logs".to_owned()),
                },
            );
            let status = envelope(&hello_b, 1, 1, GreeterRequest::Status);
            let barrier = Arc::new(Barrier::new(2));
            let left = {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || send_envelope(client_a, login, Some(barrier)))
            };
            let right = {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || send_envelope(client_b, status, Some(barrier)))
            };
            let (client_a, _) = left.join().unwrap();
            let (client_b, _) = right.join().unwrap();
            drop(client_a);
            assert!(server_a_thread.join().unwrap().is_ok());

            let cancel = envelope(
                &hello_b,
                2,
                2,
                GreeterRequest::Cancel { request_id: RequestId(1) },
            );
            let (client_b, _) = send_envelope(client_b, cancel, None);
            drop(client_b);
            assert!(server_b_thread.join().unwrap().is_ok());

            let (server_c, client_c) = UnixStream::pair().unwrap();
            let handler_c = Arc::clone(&handler);
            let expected_c = expected.clone();
            let server_c_thread = thread::spawn(move || {
                handle_client(server_c, handler_c.as_ref(), &expected_c, "seat0")
            });
            let (mut client_c, _hello_c) = handshake_client(client_c);
            write_json_line(&mut client_c, &stale).unwrap();
            drop(client_c);
            assert!(server_c_thread.join().unwrap().is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }
}
