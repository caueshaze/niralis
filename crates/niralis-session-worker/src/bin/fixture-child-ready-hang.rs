use std::io::Write;
use std::thread;
use std::time::Duration;

fn main() {
    let mut stdin = std::io::stdin();
    let mut request = Vec::new();
    let _ = std::io::BufRead::read_until(
        &mut std::io::BufReader::new(&mut stdin),
        b'\n',
        &mut request,
    );
    let response = serde_json::json!({
        "version": 8,
        "message": {
            "Ready": {
                "canonical_username": "canonical-user",
                "session_id": "niri",
                "child_pid": std::process::id(),
                "applied_credentials": {
                    "uid": 1000,
                    "gid": 1000,
                    "supplementary_gids": [10, 20]
                },
                "credential_proof": {"real_uid": 1000, "effective_uid": 1000, "saved_uid": 1000, "real_gid": 1000, "effective_gid": 1000, "saved_gid": 1000, "supplementary_gids": [10, 20]},
                "isolation_proof": {
                    "effective_capabilities": [], "permitted_capabilities": [], "inheritable_capabilities": [],
                    "ambient_capabilities": [], "bounding_capabilities": [0], "cap_last_cap": 0,
                    "securebits": 0, "no_new_privs": false, "open_fds": [0, 1, 2]
                },
                "process_identity": {"pid": std::process::id(), "sid": std::process::id(), "pgid": std::process::id()},
                "runtime_environment": {"home": {"bytes": [47,104,111,109,101,47,116,101,115,116]}, "user": "canonical-user", "logname": "canonical-user", "shell": {"bytes": [47,98,105,110,47,98,97,115,104]}, "path": "/usr/local/bin:/usr/bin:/bin", "session_type": "wayland", "cwd": {"bytes": [47,104,111,109,101,47,116,101,115,116]}, "exec_plan": {"source_path": [47,115,111,117,114,99,101,46,100,101,115,107,116,111,112], "executable": [47,98,105,110,116,114,117,101], "argv": [[116,114,117,101]]}},
                "exec_probe_version": 2
            }
        }
    });
    let mut stdout = std::io::stdout();
    let _ = serde_json::to_writer(&mut stdout, &response);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    let mut commit = Vec::new();
    let _ =
        std::io::BufRead::read_until(&mut std::io::BufReader::new(&mut stdin), b'\n', &mut commit);
    unsafe {
        libc::close(4);
    }
    thread::sleep(Duration::from_secs(5));
}
