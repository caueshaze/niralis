use std::collections::HashSet;

fn lookup_passwd(username: &CStr, buffer: &mut [libc::c_char]) -> NssLookupResult {
    // SAFETY: all pointers reference valid writable storage for the duration of
    // this reentrant NSS call. The passwd fields are copied before returning.
    unsafe {
        let mut passwd: libc::passwd = std::mem::zeroed();
        let mut result = std::ptr::null_mut();
        let status = libc::getpwnam_r(username.as_ptr(), &mut passwd, buffer.as_mut_ptr(), buffer.len(), &mut result);
        if status == libc::ERANGE { return NssLookupResult::Retry; }
        if status != 0 { return NssLookupResult::Error(io::Error::from_raw_os_error(status)); }
        if result.is_null() { return NssLookupResult::NotFound; }
        let canonical_name = CStr::from_ptr(passwd.pw_name).to_string_lossy().into_owned();
        NssLookupResult::Found(GreeterIdentity { username: canonical_name, uid: passwd.pw_uid, gid: passwd.pw_gid })
    }
}

fn handle_client<H>(mut stream: UnixStream, handler: &H, expected_peer: &GreeterIdentity, seat: &str) -> Result<()>
where H: RequestHandler {
    let peer = peer_credentials(&stream)?;
    if peer.uid != expected_peer.uid || peer.gid != expected_peer.gid {
        return Err(NiralisdError::PeerCredentialsRejected);
    }
    let handshake: GreeterHandshake = serde_json::from_slice(&read_frame(&mut stream)?)
        .map_err(|_| NiralisdError::ProtocolRejected("invalid handshake"))?;
    if handshake.protocol_version != GREETER_PROTOCOL_VERSION || handshake.message_type != "handshake" {
        return Err(NiralisdError::ProtocolRejected("invalid handshake"));
    }
    let authority = next_connection_authority(seat, peer)?;
    let _cleanup = ConnectionCleanup { handler, authority: &authority };
    write_json_line(&mut stream, &GreeterHandshakeResponse {
        protocol_version: GREETER_PROTOCOL_VERSION, connection_id: authority.connection_id().clone(),
        connection_epoch: authority.connection_epoch(), seat: authority.seat().clone(),
    })?;
    let mut sequence = niralis_protocol::MonotonicSequence::default();
    let mut request_ids = HashSet::new();
    loop {
        let frame = match read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(NiralisdError::FrameTruncated) => break,
            Err(error) => return Err(error),
        };
        let envelope: GreeterRequestEnvelope = serde_json::from_slice(&frame)
            .map_err(|_| NiralisdError::ProtocolRejected("invalid envelope"))?;
        envelope.validate_shape().map_err(|_| NiralisdError::ProtocolRejected("invalid envelope"))?;
        if !authority.matches(&envelope.connection_id, envelope.connection_epoch, &envelope.seat) {
            return Err(NiralisdError::ConnectionAuthorityRejected);
        }
        if sequence.accept(envelope.sequence).is_err() {
            return Err(NiralisdError::ProtocolRejected("non-monotonic sequence"));
        }
        let request_id = envelope.request_id;
        if !request_ids.insert(request_id.0) {
            return Err(NiralisdError::ProtocolRejected("duplicate request id"));
        }
        let request = match envelope.payload {
            GreeterRequest::Status => NiralisRequest::Status,
            GreeterRequest::GetUsers => NiralisRequest::GetUsers,
            GreeterRequest::GetSessions => NiralisRequest::GetSessions,
            GreeterRequest::Login { username, session, secret } => NiralisRequest::Login {
                username, password: secret.consume().to_string(), session,
            },
            GreeterRequest::Cancel { request_id: target } => {
                let result = handler.cancel_authenticated(&authority, request_id.0, target.0);
                write_response(&mut stream, &GreeterResponseEnvelope {
                    request_id, connection_epoch: authority.connection_epoch(), result,
                })?;
                continue;
            }
        };
        let result = handler.handle_authenticated(&authority, request_id.0, request);
        write_response(&mut stream, &GreeterResponseEnvelope {
            request_id, connection_epoch: authority.connection_epoch(), result,
        })?;
    }
    Ok(())
}

struct ConnectionCleanup<'a, H: RequestHandler> { handler: &'a H, authority: &'a GreeterConnectionAuthority }

impl<H: RequestHandler> Drop for ConnectionCleanup<'_, H> {
    fn drop(&mut self) { self.handler.connection_closed(self.authority); }
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        if frame.len() >= MAX_GREETER_FRAME_BYTES { return Err(NiralisdError::FrameTooLarge); }
        if stream.read(&mut byte)? == 0 { return Err(NiralisdError::FrameTruncated); }
        frame.push(byte[0]);
        if byte[0] == b'\n' { frame.pop(); return Ok(frame); }
    }
}

fn peer_credentials(stream: &UnixStream) -> Result<crate::connection::ValidatedPeerIdentity> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials points to writable storage of the declared size.
    let status = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
        (&mut credentials as *mut libc::ucred).cast(), &mut length) };
    if status != 0 { return Err(NiralisdError::PeerCredentialsUnavailable); }
    Ok(crate::connection::ValidatedPeerIdentity { uid: credentials.uid, gid: credentials.gid, pid: Some(credentials.pid) })
}

fn write_response(writer: &mut UnixStream, response: &GreeterResponseEnvelope) -> Result<()> {
    let encoded = serde_json::to_vec(response)?;
    if encoded.len() > MAX_GREETER_FRAME_BYTES {
        return write_json_line(writer, &GreeterResponseEnvelope {
            request_id: response.request_id, connection_epoch: response.connection_epoch,
            result: niralis_protocol::NiralisResponse::Error { message: "response unavailable".to_owned() },
        });
    }
    writer.write_all(&encoded)?; writer.write_all(b"\n")?; writer.flush()?; Ok(())
}

fn write_json_line<T: serde::Serialize>(writer: &mut UnixStream, value: &T) -> Result<()> {
    let encoded = serde_json::to_vec(value)?;
    if encoded.len() > MAX_GREETER_FRAME_BYTES {
        return Err(NiralisdError::FrameTooLarge);
    }
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}
