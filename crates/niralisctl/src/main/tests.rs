#[cfg(test)]
mod tests {
    use super::read_password_line;
    use std::io::Cursor;

    #[test]
    fn password_stdin_preserves_password_bytes_except_line_ending() {
        for (input, expected) in [
            ("secret\n", "secret"),
            ("secret\r\n", "secret"),
            ("secret", "secret"),
            ("\n", ""),
            (" senha ", " senha "),
        ] {
            assert_eq!(read_password_line(Cursor::new(input)).unwrap(), expected);
        }
    }

    #[test]
    fn password_stdin_rejects_immediate_eof() {
        assert!(read_password_line(Cursor::new("")).is_err());
    }
}
