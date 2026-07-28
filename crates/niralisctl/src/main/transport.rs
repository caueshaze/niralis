fn print_recovery_response(response: &RecoveryAdminResponse, json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string_pretty(response)?);
        return Ok(());
    }
    match response {
        RecoveryAdminResponse::Inspection(inspection) => {
            println!(
                "seat: {}\nrecord: {}\nsequence: {}\ntarget_vt: {}\nquarantine_reason: {}",
                inspection.seat,
                inspection.record_id,
                inspection.sequence,
                inspection.target_vt,
                inspection.quarantine_reason.as_deref().unwrap_or("none")
            );
            if let Some(provenance) = &inspection.provenance {
                println!(
                    "classification: {:?}\nactive_vt: {:?}\nholders: {}\ninspection_failures: {}",
                    provenance.classification,
                    provenance.observed_active_vt,
                    provenance.visible_holders.len(),
                    provenance.inspection_failures.len()
                );
            }
            println!(
                "operations: {:#?}\nrecovery_attempts: {}",
                inspection.operation_ledger,
                inspection.attempts.len()
            );
        }
        RecoveryAdminResponse::RetryAccepted {
            record_id,
            sequence,
            attempt_id,
        } => println!(
            "recovery attempt {} completed for {} at sequence {}",
            attempt_id, record_id, sequence
        ),
        RecoveryAdminResponse::Rejected { reason, sequence } => println!(
            "recovery rejected: {}{}",
            reason,
            sequence
                .map(|value| format!(" (current sequence {value})"))
                .unwrap_or_default()
        ),
    }
    Ok(())
}

fn read_password_line(mut reader: impl BufRead) -> Result<String, CliError> {
    let mut password = String::new();
    if reader.read_line(&mut password)? == 0 {
        return Err(CliError::PasswordStdinEof);
    }
    if password.ends_with("\r\n") {
        password.truncate(password.len() - 2);
    } else if password.ends_with('\n') {
        password.pop();
    }
    Ok(password)
}

fn send_request(socket: &PathBuf, request: &NiralisRequest) -> Result<NiralisResponse, CliError> {
    let mut stream = UnixStream::connect(socket)?;
    serde_json::to_writer(
        &mut stream,
        &GreeterHandshake {
            protocol_version: GREETER_PROTOCOL_VERSION,
            message_type: "handshake".to_owned(),
        },
    )?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    read_greeter_line(&mut reader, &mut line)?;
    let handshake: GreeterHandshakeResponse = serde_json::from_str(line.trim_end())?;
    if handshake.protocol_version != GREETER_PROTOCOL_VERSION
        || handshake.connection_epoch == 0
        || handshake.connection_id.as_str().is_empty()
        || handshake.seat.as_str().is_empty()
    {
        return Err(CliError::GreeterProtocol(
            "invalid handshake response".to_owned(),
        ));
    }
    line.clear();
    let payload = match request {
        NiralisRequest::Status => GreeterRequest::Status,
        NiralisRequest::GetUsers => GreeterRequest::GetUsers,
        NiralisRequest::GetSessions => GreeterRequest::GetSessions,
        NiralisRequest::Login {
            username,
            password,
            session,
        } => GreeterRequest::Login {
            username: username.clone(),
            session: session.clone(),
            secret: LoginSecret::new(password.clone()),
        },
        NiralisRequest::Shutdown | NiralisRequest::Reboot => {
            return Ok(NiralisResponse::Error {
                message: "not implemented".to_owned(),
            });
        }
    };
    let payload_len = serde_json::to_vec(&payload)?.len();
    let message_type = match &payload {
        GreeterRequest::Status => "status",
        GreeterRequest::GetUsers => "get_users",
        GreeterRequest::GetSessions => "get_sessions",
        GreeterRequest::Login { .. } => "login",
        GreeterRequest::Cancel { .. } => "cancel",
    };
    let envelope = GreeterRequestEnvelope {
        protocol_version: GREETER_PROTOCOL_VERSION,
        message_type: message_type.to_owned(),
        connection_id: handshake.connection_id,
        connection_epoch: handshake.connection_epoch,
        request_id: RequestId(1),
        sequence: 1,
        seat: handshake.seat,
        payload_len,
        payload,
    };
    serde_json::to_writer(reader.get_mut(), &envelope)?;
    reader.get_mut().write_all(b"\n")?;
    reader.get_mut().flush()?;
    line.clear();
    read_greeter_line(&mut reader, &mut line)?;

    let response: GreeterResponseEnvelope = serde_json::from_str(line.trim_end())?;
    if response.request_id != RequestId(1)
        || response.connection_epoch != handshake.connection_epoch
    {
        return Err(CliError::GreeterProtocol(
            "response correlation mismatch".to_owned(),
        ));
    }
    Ok(response.result)
}

fn read_greeter_line(
    reader: &mut BufReader<UnixStream>,
    line: &mut String,
) -> Result<(), CliError> {
    let bytes = reader.read_line(line)?;
    if bytes == 0 {
        return Err(CliError::GreeterProtocol("unexpected end of stream".to_owned()));
    }
    if bytes > MAX_GREETER_FRAME_BYTES || !line.ends_with('\n') {
        return Err(CliError::GreeterProtocol("invalid frame".to_owned()));
    }
    Ok(())
}

fn print_response(response: &NiralisResponse) {
    match response {
        NiralisResponse::Status { status } => {
            println!("version: {}", status.version);
            println!("socket: {}", status.socket);
            println!("default_session: {}", status.default_session);
            println!("greeter_user: {}", status.greeter_user);
        }
        NiralisResponse::Users { users } => {
            for user in users {
                println!("{}\t{}", user.username, user.display_name);
            }
        }
        NiralisResponse::Sessions { sessions } => {
            for session in sessions {
                let kind = match session.kind {
                    SessionKind::Wayland => "wayland",
                    SessionKind::X11 => "x11",
                };
                println!("{}\t{}\t{}", session.id, session.name, kind);
            }
        }
        NiralisResponse::LoginOk { session } => {
            println!(
                "login ok: id={} name={} kind={}",
                session.id,
                session.name,
                match session.kind {
                    SessionKind::Wayland => "wayland",
                    SessionKind::X11 => "x11",
                }
            );
        }
        NiralisResponse::SessionUnavailable { message } => {
            eprintln!("niralisctl: {message}");
        }
        NiralisResponse::LoginFailed { message } | NiralisResponse::Error { message } => {
            println!("{message}");
        }
    }
}
