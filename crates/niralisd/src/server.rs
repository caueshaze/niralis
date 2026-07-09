use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use niralis_protocol::{NiralisRequest, NiralisResponse};
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::config::Config;
use crate::error::{NiralisdError, Result};
use crate::handler::RequestHandler;

pub fn run<H>(config: &Config, handler: H) -> Result<()>
where
    H: RequestHandler + 'static,
{
    let listener = bind_socket(&config.daemon.socket)?;
    let handler = Arc::new(handler);

    info!(socket = %config.daemon.socket.display(), "niralisd listening");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let handler = Arc::clone(&handler);
                if let Err(error) = handle_client(stream, handler.as_ref()) {
                    warn!(%error, "failed to handle ipc client");
                }
            }
            Err(error) => warn!(%error, "failed to accept ipc client"),
        }
    }

    Ok(())
}

fn bind_socket(socket_path: &Path) -> Result<UnixListener> {
    let runtime_dir = socket_path
        .parent()
        .ok_or_else(|| NiralisdError::InvalidSocketPath(socket_path.to_path_buf()))?;

    fs::create_dir_all(runtime_dir)?;
    fs::set_permissions(runtime_dir, fs::Permissions::from_mode(0o755))?;

    if socket_path.exists() {
        let metadata = fs::metadata(socket_path)?;
        if metadata.file_type().is_socket() {
            fs::remove_file(socket_path)?;
        } else {
            return Err(NiralisdError::InvalidSocketPath(socket_path.to_path_buf()));
        }
    }

    let listener = UnixListener::bind(socket_path)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;

    Ok(listener)
}

fn handle_client<H>(stream: UnixStream, handler: &H) -> Result<()>
where
    H: RequestHandler,
{
    let writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut line = Zeroizing::new(String::new());

    reader.read_line(&mut *line)?;
    debug!("received ipc request");

    let response = if line.trim().is_empty() {
        NiralisResponse::Error {
            message: "empty request".to_owned(),
        }
    } else {
        let request: NiralisRequest = serde_json::from_str(line.trim_end())?;
        (*line).zeroize();
        handler.handle(request)
    };

    write_response(writer, &response)?;

    Ok(())
}

fn write_response(mut writer: UnixStream, response: &NiralisResponse) -> Result<()> {
    serde_json::to_writer(&mut writer, response)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}
