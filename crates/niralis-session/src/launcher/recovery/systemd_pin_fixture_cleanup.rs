use super::*;

impl Drop for SystemdScopeFixture {
    fn drop(&mut self) {
        if !self.cleanup_needed {
            return;
        }
        let connection = match zbus::blocking::connection::Builder::system()
            .and_then(|builder| builder.build())
        {
            Ok(connection) => connection,
            Err(_) => return,
        };
        let Ok(Some(path)) = resolve_invocation(&connection, &self.invocation) else {
            return;
        };
        let Ok(observation) = read_unit_observation(&connection, &path) else {
            return;
        };
        if path.as_str() != self.object_path
            || observation.id != self.unit
            || observation.invocation_id != self.invocation
            || observation.control_group != self.control_group
            || observation.slice != self.slice
            || !observation.transient
        {
            return;
        }
        if std::path::Path::new(&format!("/proc/{}", self.leader_pid)).exists() {
            let _ = unit_call(&connection, &path, "Kill", &("all", libc::SIGKILL));
        }
        terminate_fixture_launcher(&mut self.launcher);
        let _ = unit_call(&connection, &path, "Unref", &());
    }
}

pub(super) fn terminate_fixture_launcher(launcher: &mut Child) {
    if launcher.try_wait().ok().flatten().is_none() {
        let _ = launcher.kill();
        let _ = launcher.wait();
    }
}
