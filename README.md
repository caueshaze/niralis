# Niralis

Niralis is a future Wayland-first display manager and greeter stack written in
Rust. This repository currently contains the phase 1 daemon foundation.

## Phase 1

- `niralisd`: main daemon, config loading, Unix socket IPC, mock login flow.
- `niralis-protocol`: shared serde IPC types.
- `niralis-auth`: mock authentication behind an `Authenticator` trait.
- `niralis-session`: mock session launcher behind a `SessionLauncher` trait.
- `niralisctl`: small CLI for status, users, and mock login.

## Local Smoke Test

Use a temporary config so the daemon does not need write access to `/run`:

```toml
[daemon]
socket = "/tmp/niralis-test/niralisd.sock"
log_level = "info"

[greeter]
command = "/usr/bin/niralis-greeter"
user = "niralis"

[auth]
pam_service = "niralis"
max_attempts = 5
cooldown_seconds = 10

[session]
default = "niri"
command = "niri-session"
```

Then run:

```sh
cargo run -p niralisd -- --config /tmp/niralis-test/niralis.toml
cargo run -p niralisctl -- --socket /tmp/niralis-test/niralisd.sock status
cargo run -p niralisctl -- --socket /tmp/niralis-test/niralisd.sock users
cargo run -p niralisctl -- --socket /tmp/niralis-test/niralisd.sock login --user test --password test --session niri
```
