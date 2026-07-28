static NEXT_CONNECTION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static NEXT_CONNECTION_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static DAEMON_GENERATION: std::sync::OnceLock<std::result::Result<u64, ()>> = std::sync::OnceLock::new();

fn daemon_generation() -> crate::error::Result<u64> {
    DAEMON_GENERATION
        .get_or_init(|| {
            let mut bytes = [0u8; std::mem::size_of::<u64>()];
            let result = unsafe {
                libc::getrandom(
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::GRND_NONBLOCK,
                )
            };
            if result == bytes.len() as isize {
                Ok(u64::from_ne_bytes(bytes).max(1))
            } else {
                Err(())
            }
        })
        .as_ref()
        .copied()
        .map_err(|_| crate::error::NiralisdError::ConnectionGenerationUnavailable)
}

fn next_connection_authority(
    seat: &str,
    peer: crate::connection::ValidatedPeerIdentity,
) -> crate::error::Result<crate::connection::GreeterConnectionAuthority> {
    let generation = daemon_generation()?;
    let ordinal = NEXT_CONNECTION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let epoch = generation
        .wrapping_add(NEXT_CONNECTION_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        .max(1);
    Ok(crate::connection::GreeterConnectionAuthority::issue(
        niralis_protocol::GreeterConnectionId::new_for_wire(
            format!("g{generation:016x}-c{ordinal}"),
        ),
        epoch,
        niralis_protocol::SeatId::new_for_wire(seat.to_owned()),
        peer,
    ))
}
