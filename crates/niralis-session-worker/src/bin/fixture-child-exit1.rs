use std::io::{Read, Write};

fn main() {
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
    let response = serde_json::json!({
        "version": 2,
        "message": {
            "Ready": {
                "canonical_username": "canonical-user",
                "session_id": "niri",
                "child_pid": std::process::id(),
                "applied_credentials": {
                    "uid": 1000,
                    "gid": 1000,
                    "supplementary_gids": [10, 20]
                }
            }
        }
    });
    let mut stdout = std::io::stdout();
    let _ = serde_json::to_writer(&mut stdout, &response);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    std::process::exit(1);
}
