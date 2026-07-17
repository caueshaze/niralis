
#[cfg(test)]
struct NoopFdSanitizer;
#[cfg(test)]
impl InheritedFdSanitizer for NoopFdSanitizer {
    fn sanitize(&self) -> Result<(), crate::isolation::FdSanitizationError> {
        Ok(())
    }
}

#[cfg(test)]
struct StubAudit;
#[cfg(test)]
impl PostDropAuditor for StubAudit {
    fn audit(&self) -> Result<PostDropIsolationProof, crate::isolation::PostDropAuditError> {
        Ok(PostDropIsolationProof {
            capabilities: crate::isolation::CapabilityState {
                effective: vec![],
                permitted: vec![],
                inheritable: vec![],
                ambient: vec![],
                bounding: vec![],
                cap_last_cap: 0,
            },
            securebits: 0,
            no_new_privs: false,
            open_fds: vec![0, 1, 2],
        })
    }
}

fn parse_request(
    bytes: &[u8],
) -> Result<SessionChildEnvelope<SessionChildRequest>, SessionChildErrorCode> {
    if bytes.is_empty()
        || bytes.len() > protocol::MAX_SESSION_CHILD_MESSAGE_BYTES
        || !bytes.ends_with(b"\n")
    {
        return Err(SessionChildErrorCode::InvalidRequest);
    }
    serde_json::from_slice(&bytes[..bytes.len() - 1])
        .map_err(|_| SessionChildErrorCode::InvalidRequest)
}

fn write_rejection(writer: &mut impl Write, code: SessionChildErrorCode) -> std::io::Result<()> {
    let response = SessionChildEnvelope {
        version: SESSION_CHILD_PROTOCOL_VERSION,
        message: SessionChildResponse::Rejected { code },
    };
    serde_json::to_writer(&mut *writer, &response)?;
    writer.write_all(b"\n")
}

#[cfg(test)]
mod tests;
