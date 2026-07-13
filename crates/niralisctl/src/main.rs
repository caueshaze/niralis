use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use niralis_protocol::{NiralisRequest, NiralisResponse, SessionKind};
use thiserror::Error;

const DEFAULT_SOCKET_PATH: &str = "/run/niralis/niralisd.sock";

#[derive(Debug, Parser)]
#[command(version, about = "Control CLI for niralisd")]
struct Cli {
    #[arg(long, env = "NIRALISD_SOCKET", default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status,
    Users,
    Sessions,
    Login {
        #[arg(long)]
        user: String,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        session: String,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error("login requires --password-stdin")]
    PasswordStdinRequired,
    #[error("password stdin ended before a line was read")]
    PasswordStdinEof,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ipc json error: {0}")]
    Json(#[from] serde_json::Error),
}

fn main() {
    if let Err(error) = run() {
        eprintln!("niralisctl: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let request = match cli.command {
        Command::Status => NiralisRequest::Status,
        Command::Users => NiralisRequest::GetUsers,
        Command::Sessions => NiralisRequest::GetSessions,
        Command::Login {
            user,
            password_stdin,
            session,
        } => {
            if !password_stdin {
                return Err(CliError::PasswordStdinRequired);
            }
            NiralisRequest::Login {
                username: user,
                password: read_password_line(io::stdin().lock())?,
                session,
            }
        }
    };

    let response = send_request(&cli.socket, &request)?;
    print_response(&response);

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
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    Ok(serde_json::from_str(line.trim_end())?)
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
