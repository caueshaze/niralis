use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use niralis_protocol::{NiralisRequest, NiralisResponse, SessionKind};
use niralis_session::{
    RecoveryAdminEnvelope, RecoveryAdminRequest, RecoveryAdminResponse,
    MAX_RECOVERY_ADMIN_PACKET_BYTES, RECOVERY_ADMIN_PROTOCOL_VERSION,
};
use thiserror::Error;

const DEFAULT_SOCKET_PATH: &str = "/run/niralis/niralisd.sock";
const RECOVERY_ADMIN_SOCKET: &str = "/run/niralis/recovery-admin/recovery.sock";

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
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RecoveryCommand {
    InspectVt {
        #[arg(long)]
        seat: String,
        #[arg(long)]
        record_id: String,
        #[arg(long)]
        json: bool,
    },
    RetryVtDisallocate {
        #[arg(long)]
        seat: String,
        #[arg(long)]
        record_id: String,
        #[arg(long)]
        record_sequence: u64,
        #[arg(long)]
        acknowledge_indeterminate: Option<u64>,
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
    #[error("recovery administration requires uid 0")]
    RecoveryRequiresRoot,
    #[error("recovery administration protocol error: {0}")]
    RecoveryProtocol(String),
}

fn main() {
    if let Err(error) = run() {
        eprintln!("niralisctl: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    if let Command::Recovery { command } = cli.command {
        if unsafe { libc::geteuid() } != 0 {
            return Err(CliError::RecoveryRequiresRoot);
        }
        let (request, json) = match command {
            RecoveryCommand::InspectVt {
                seat,
                record_id,
                json,
            } => (RecoveryAdminRequest::InspectVt { seat, record_id }, json),
            RecoveryCommand::RetryVtDisallocate {
                seat,
                record_id,
                record_sequence,
                acknowledge_indeterminate,
            } => (
                RecoveryAdminRequest::RetryVtDisallocate {
                    seat,
                    record_id,
                    record_sequence,
                    acknowledge_indeterminate,
                },
                false,
            ),
        };
        let response = send_recovery_request(&request)?;
        print_recovery_response(&response, json)?;
        return Ok(());
    }
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
        Command::Recovery { .. } => {
            unreachable!("recovery command handled before public socket dispatch")
        }
    };

    let response = send_request(&cli.socket, &request)?;
    print_response(&response);

    Ok(())
}

fn send_recovery_request(
    request: &RecoveryAdminRequest,
) -> Result<RecoveryAdminResponse, CliError> {
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: socket returned a fresh descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let path = std::path::Path::new(RECOVERY_ADMIN_SOCKET);
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(CliError::RecoveryProtocol(
            "invalid recovery administration socket path".to_owned(),
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (index, byte) in bytes.iter().enumerate() {
        address.sun_path[index] = *byte as libc::c_char;
    }
    let length = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let request = serde_json::to_vec(&RecoveryAdminEnvelope {
        version: RECOVERY_ADMIN_PROTOCOL_VERSION,
        message: request,
    })?;
    if request.len() > MAX_RECOVERY_ADMIN_PACKET_BYTES {
        return Err(CliError::RecoveryProtocol("request too large".to_owned()));
    }
    if unsafe {
        libc::send(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let mut buffer = vec![0_u8; MAX_RECOVERY_ADMIN_PACKET_BYTES];
    let received = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_TRUNC,
        )
    };
    if received <= 0 || received as usize > buffer.len() {
        return Err(CliError::RecoveryProtocol(
            "invalid response packet".to_owned(),
        ));
    }
    let envelope: RecoveryAdminEnvelope<RecoveryAdminResponse> =
        serde_json::from_slice(&buffer[..received as usize])?;
    if envelope.version != RECOVERY_ADMIN_PROTOCOL_VERSION {
        return Err(CliError::RecoveryProtocol(
            "unsupported response version".to_owned(),
        ));
    }
    Ok(envelope.message)
}

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
