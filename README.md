# Niralis

Niralis is a future Wayland-first display manager and greeter stack written in
Rust. This repository currently contains the daemon foundation with real PAM
authentication and mock session startup.

## Crates

- `niralisd`: main daemon, config loading, Unix socket IPC, auth flow, rate limit.
- `niralis-protocol`: shared serde IPC types.
- `niralis-auth`: PAM and mock authentication behind an `Authenticator` trait.
- `niralis-session`: mock session launcher behind a `SessionLauncher` trait.
- `niralisctl`: small CLI for status, users, and login.

## Build Requirements

The PAM backend uses the Rust `pam` crate, which builds `pam-sys` with
`bindgen`. Development machines need PAM headers plus Clang/LLVM development
files available to the build. A correctly prepared system should provide both:

```sh
which llvm-config
find /usr/lib64 -name 'libclang.so'
```

On openSUSE, install the development packages that provide those files, for
example `clang-devel` and `llvm-devel`. Other distributions use equivalent
packages such as `libclang-dev`/`clang` on Debian or Ubuntu, `clang-devel` and
`llvm-devel` on Fedora, or `clang` on Arch.

## Auth Backends

Production config defaults to PAM:

```toml
[auth]
backend = "pam"
pam_service = "niralis"
max_attempts = 5
cooldown_seconds = 10
```

For local smoke tests without PAM, use the mock backend:

```toml
[auth]
backend = "mock"
pam_service = "niralis"
max_attempts = 5
cooldown_seconds = 10
```

## Local Mock Smoke Test

Use a temporary config so the daemon does not need write access to `/run`:

```toml
[daemon]
socket = "/tmp/niralis-test/niralisd.sock"
log_level = "info"

[greeter]
command = "/usr/bin/niralis-greeter"
user = "niralis"

[auth]
backend = "mock"
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
printf '%s\n' test | cargo run -p niralisctl -- --socket /tmp/niralis-test/niralisd.sock login --user test --password-stdin --session niri
```

## Rebuild, install, and installed smoke

For local development, use the repository-owned installer rather than copying
individual binaries by hand. It uses one canonical layout:

```text
/usr/sbin/niralisd
/usr/bin/niralisctl
/usr/libexec/niralis-session-worker
/usr/libexec/niralis-session-child
/usr/libexec/niralis-session-probe
```

The first installation on an SELinux host also installs the local policy. This
does not overwrite `/etc/niralis/niralis.toml` or the PAM service file:

```sh
./scripts/install-local.sh --install-selinux-policy
```

For the normal edit/build/install/restart loop, when no Niralis graphical
session is active:

```sh
./scripts/install-local.sh --restart
./scripts/smoke-installed.sh --ipc
sudo journalctl -u niralisd -f
```

`smoke-installed.sh` checks the installed paths, service, socket, and SELinux
labels. With `--ipc`, it additionally sends only the read-only `status` IPC
request as the `niralis` account by default; pass `--ipc-user USER` if the
configured greeter has another identity. It never authenticates, opens PAM,
allocates a VT, or launches a graphical session. Pass `--socket PATH` for a
non-default test socket. The installer runs the full workspace tests by
default; use `--skip-tests` only when they have already been run for the same
build.

The installer refuses `--restart` if a systemd drop-in overrides the canonical
`ExecStart`. Remove obsolete local smoke overrides that point to an old daemon
path, then run `sudo systemctl daemon-reload` and the installer again. The
real-graphical gate and logging drop-ins may remain; only an `ExecStart=` reset
or replacement is incompatible with this layout.

## PAM Setup

An example PAM service file is provided at `config/pam/niralis`. Install it
manually as `/etc/pam.d/niralis` before testing the PAM backend. On openSUSE the
example uses the common PAM stacks:

```text
auth     include common-auth
account  include common-account
password include common-password
session  include common-session
```

After installing the PAM file, run the daemon with `backend = "pam"` and test
with a real local user. This phase authenticates only; it still does not open a
PAM session or start a graphical session.
