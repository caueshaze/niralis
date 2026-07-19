use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[path = "../fixture_dbus_systemd_helpers.rs"]
mod fixture_dbus_systemd_helpers;
use fixture_dbus_systemd_helpers::{append, hex, parse_hex, send_pidfd};

#[derive(Clone)]
struct State {
    unit: String,
    invocation: String,
    object_path: String,
    control_group: String,
    leader_pid: u32,
    leader_starttime: u64,
    member_pid: u32,
    member_starttime: u64,
    operation_log: PathBuf,
}

fn main() {
    if run().is_err() {
        eprintln!("fixture-dbus-systemd failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let mut args = std::env::args().skip(1);
    let address = args.next().ok_or(())?;
    let unit = args.next().ok_or(())?;
    let invocation = args.next().ok_or(())?;
    let object_path = args.next().ok_or(())?;
    let control_group = args.next().ok_or(())?;
    let leader_pid = args.next().ok_or(())?.parse().map_err(|_| ())?;
    let leader_starttime = args.next().ok_or(())?.parse().map_err(|_| ())?;
    let member_pid = args.next().ok_or(())?.parse().map_err(|_| ())?;
    let member_starttime = args.next().ok_or(())?.parse().map_err(|_| ())?;
    let ready_path = args.next().ok_or(())?;
    let operation_log = PathBuf::from(args.next().ok_or(())?);
    let state = Arc::new(Mutex::new(State {
        unit,
        invocation,
        object_path: object_path.clone(),
        control_group,
        leader_pid,
        leader_starttime,
        member_pid,
        member_starttime,
        operation_log,
    }));
    let manager = FakeManager(Arc::clone(&state));
    let unit_iface = FakeUnit(Arc::clone(&state));
    let scope_iface = FakeScope(Arc::clone(&state));
    let connection = zbus::blocking::connection::Builder::address(address.as_str())
        .and_then(|builder| builder.name("org.freedesktop.systemd1"))
        .and_then(|builder| builder.serve_at("/org/freedesktop/systemd1", manager))
        .and_then(|builder| builder.serve_at(object_path.as_str(), unit_iface))
        .and_then(|builder| builder.serve_at(object_path.as_str(), scope_iface))
        .and_then(|builder| builder.build())
        .map_err(|error| {
            eprintln!("fixture-dbus-systemd build error: {error:?}");
        })?;
    let mut ready = UnixStream::connect(ready_path).map_err(|error| {
        eprintln!("fixture-dbus-systemd ready error: {error:?}");
    })?;
    writeln!(ready, "ready").map_err(|_| ())?;
    for line in io::stdin().lock().lines() {
        if matches!(line.as_deref(), Ok("exit")) {
            break;
        }
    }
    drop(connection);
    Ok(())
}

#[derive(Clone)]
struct FakeManager(Arc<Mutex<State>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl FakeManager {
    #[zbus(name = "GetUnitByInvocationID")]
    fn get_unit_by_invocation_id(
        &self,
        invocation: Vec<u8>,
    ) -> zbus::fdo::Result<zbus::zvariant::OwnedObjectPath> {
        let state = self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?;
        if hex(&invocation) != state.invocation {
            return Err(zbus::fdo::Error::Failed(
                "org.freedesktop.systemd1.NoSuchUnit".into(),
            ));
        }
        state
            .object_path
            .as_str()
            .try_into()
            .map_err(|_| zbus::fdo::Error::Failed("object path".into()))
    }

    fn list_units(
        &self,
    ) -> zbus::fdo::Result<
        Vec<(
            String,
            String,
            String,
            String,
            String,
            String,
            zbus::zvariant::OwnedObjectPath,
            u32,
            String,
            zbus::zvariant::OwnedObjectPath,
        )>,
    > {
        let state = self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?;
        Ok(vec![(
            state.unit.clone(),
            "fixture".to_owned(),
            "loaded".to_owned(),
            "active".to_owned(),
            "running".to_owned(),
            "fixture".to_owned(),
            zbus::zvariant::OwnedObjectPath::try_from(state.object_path.as_str())
                .map_err(|_| zbus::fdo::Error::Failed("path".into()))?,
            0,
            "".to_owned(),
            zbus::zvariant::OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/fixture")
                .map_err(|_| zbus::fdo::Error::Failed("path".into()))?,
        )])
    }
}

#[derive(Clone)]
struct FakeUnit(Arc<Mutex<State>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl FakeUnit {
    #[zbus(property)]
    fn id(&self) -> zbus::fdo::Result<String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?
            .unit
            .clone())
    }
    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> zbus::fdo::Result<Vec<u8>> {
        let state = self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?;
        Ok(parse_hex(&state.invocation)
            .ok_or_else(|| zbus::fdo::Error::Failed("invocation".into()))?)
    }
    #[zbus(property)]
    fn transient(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn active_state(&self) -> String {
        "active".to_owned()
    }
    #[zbus(property)]
    fn sub_state(&self) -> String {
        "running".to_owned()
    }
    fn r#ref(&self) -> zbus::fdo::Result<()> {
        let state = self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?
            .clone();
        append(
            &state.operation_log,
            &format!(
                "dbus_unit_ref unit={} invocation={} object_path={}\n",
                state.unit, state.invocation, state.object_path
            ),
        );
        Ok(())
    }
    fn unref(&self) -> zbus::fdo::Result<()> {
        let state = self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?
            .clone();
        append(
            &state.operation_log,
            &format!(
                "dbus_unit_unref unit={} invocation={} object_path={}\n",
                state.unit, state.invocation, state.object_path
            ),
        );
        Ok(())
    }
    fn kill(&self, what: &str, signal: i32) -> zbus::fdo::Result<()> {
        if what != "all" || signal != libc::SIGKILL {
            return Err(zbus::fdo::Error::Failed("invalid kill".into()));
        }
        let state = self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?
            .clone();
        append(
            &state.operation_log,
            &format!(
                "dbus_unit_kill unit={} invocation={} object_path={}\n",
                state.unit, state.invocation, state.object_path
            ),
        );
        send_pidfd(state.leader_pid, state.leader_starttime)?;
        send_pidfd(state.member_pid, state.member_starttime)?;
        Ok(())
    }
}

#[derive(Clone)]
struct FakeScope(Arc<Mutex<State>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Scope")]
impl FakeScope {
    #[zbus(property)]
    fn control_group(&self) -> zbus::fdo::Result<String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("state".into()))?
            .control_group
            .clone())
    }
    #[zbus(property)]
    fn slice(&self) -> String {
        "user-1000.slice".to_owned()
    }
}
