use std::io;

pub(crate) fn validate_lifecycle_id(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.as_bytes().contains(&0)
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid lifecycle id",
        ))
    } else {
        Ok(())
    }
}
