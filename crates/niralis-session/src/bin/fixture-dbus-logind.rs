use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct State {
    session_id: String,
    object_path: String,
    uid: u32,
    username: String,
    leader: u32,
    seat: String,
    vt: u32,
    desktop: String,
    operation_log: PathBuf,
    present: bool,
}

#[derive(Clone)]
struct Manager(Arc<Mutex<State>>);

#[derive(Clone)]
struct Session(Arc<Mutex<State>>);

fn main() {
    if run().is_err() {
        eprintln!("fixture-dbus-logind failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let mut args = std::env::args().skip(1);
    let address = args.next().ok_or(())?;
    let session_id = args.next().ok_or(())?;
    let object_path = args.next().ok_or(())?;
    let uid = args.next().ok_or(())?.parse().map_err(|_| ())?;
    let username = args.next().ok_or(())?;
    let leader = args.next().ok_or(())?.parse().map_err(|_| ())?;
    let seat = args.next().ok_or(())?;
    let vt = args.next().ok_or(())?.parse().map_err(|_| ())?;
    let desktop = args.next().ok_or(())?;
    let ready_path = args.next().ok_or(())?;
    let operation_log = PathBuf::from(args.next().ok_or(())?);
    let state = Arc::new(Mutex::new(State {
        session_id,
        object_path: object_path.clone(),
        uid,
        username,
        leader,
        seat,
        vt,
        desktop,
        operation_log,
        present: true,
    }));
    let connection = zbus::blocking::connection::Builder::address(address.as_str())
        .and_then(|builder| builder.name("org.freedesktop.login1"))
        .and_then(|builder| {
            builder.serve_at("/org/freedesktop/login1", Manager(Arc::clone(&state)))
        })
        .and_then(|builder| builder.serve_at(object_path.as_str(), Session(state)))
        .and_then(|builder| builder.build())
        .map_err(|error| eprintln!("fixture-dbus-logind build error: {error:?}"))?;
    let mut ready = UnixStream::connect(ready_path).map_err(|_| ())?;
    writeln!(ready, "ready").map_err(|_| ())?;
    for line in io::stdin().lock().lines() {
        if matches!(line.as_deref(), Ok("exit")) {
            break;
        }
    }
    drop(connection);
    Ok(())
}

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    fn get_session(&self, id: &str) -> zbus::fdo::Result<zbus::zvariant::OwnedObjectPath> {
        let state = self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?;
        if state.present && id == state.session_id {
            state
                .object_path
                .as_str()
                .try_into()
                .map_err(|_| zbus::fdo::Error::Failed("path".into()))
        } else {
            Err(zbus::fdo::Error::Failed(
                "org.freedesktop.login1.NoSuchSession".into(),
            ))
        }
    }

    fn terminate_session(&self, id: &str) -> zbus::fdo::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?;
        if !state.present || id != state.session_id {
            return Err(zbus::fdo::Error::Failed(
                "org.freedesktop.login1.NoSuchSession".into(),
            ));
        }
        state.present = false;
        append(
            &state.operation_log,
            &format!("dbus_logind_terminate id={id}\n"),
        );
        Ok(())
    }
}

#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl Session {
    #[zbus(property)]
    fn id(&self) -> zbus::fdo::Result<String> {
        self.value(|s| s.session_id.clone())
    }
    #[zbus(property)]
    fn user(&self) -> zbus::fdo::Result<(u32, zbus::zvariant::OwnedObjectPath)> {
        Ok((
            self.value(|s| s.uid)?,
            "/org/freedesktop/login1/user/_1000".try_into().unwrap(),
        ))
    }
    #[zbus(property)]
    fn leader(&self) -> zbus::fdo::Result<u32> {
        self.value(|s| s.leader)
    }
    #[zbus(property)]
    fn name(&self) -> zbus::fdo::Result<String> {
        self.value(|s| s.username.clone())
    }
    #[zbus(property)]
    fn seat(&self) -> zbus::fdo::Result<(String, zbus::zvariant::OwnedObjectPath)> {
        Ok((
            self.value(|s| s.seat.clone())?,
            "/org/freedesktop/login1/seat/seat0".try_into().unwrap(),
        ))
    }
    #[zbus(property, name = "VTNr")]
    fn vt_nr(&self) -> zbus::fdo::Result<u32> {
        self.value(|s| s.vt)
    }
    #[zbus(property, name = "Type")]
    fn session_type(&self) -> String {
        "wayland".to_owned()
    }
    #[zbus(property, name = "Class")]
    fn class(&self) -> String {
        "user".to_owned()
    }
    #[zbus(property)]
    fn desktop(&self) -> zbus::fdo::Result<String> {
        self.value(|s| s.desktop.clone())
    }
    #[zbus(property)]
    fn state(&self) -> String {
        "active".to_owned()
    }
    #[zbus(property)]
    fn scope(&self) -> String {
        "session-fixture.scope".to_owned()
    }
}

impl Session {
    fn value<T>(&self, read: impl FnOnce(&State) -> T) -> zbus::fdo::Result<T> {
        let state = self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?;
        if state.present {
            Ok(read(&state))
        } else {
            Err(zbus::fdo::Error::Failed(
                "org.freedesktop.login1.NoSuchSession".into(),
            ))
        }
    }
}

fn append(path: &PathBuf, value: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = file.write_all(value.as_bytes());
    }
}
