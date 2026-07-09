# Niralisd Security Notes

This phase preserves the authenticated PAM transaction with RAII and introduces
an isolated, one-shot session worker process boundary while keeping graphical
session startup, greeter management, Wayland UI, privilege transitions, and
full session lifecycle semantics out of scope.

## Current Guarantees

- Passwords are accepted only as IPC input for login and are never written to
  logs.
- Login failure responses are generic and do not reveal whether the username,
  password, PAM service, account policy, or rate limit caused the failure.
- PAM failures return `LoginFailed` to the client.
- PAM detail, if logged at all, is restricted to `debug` or `trace`; `info` and
  `warn` logs must not contain raw PAM messages, PAM codes, or password data.
- IPC is local-only through a Unix socket.
- The daemon creates the socket with restricted permissions (`0660`).
- Login attempts are rate-limited per username before PAM is called.
- Successful login resets that user's rate limit state.
- Requested sessions are validated through discovery before PAM is called.
- Session startup can be delegated to an isolated `niralis-session-worker`
  process using a private, versioned internal protocol.
- Daemon, protocol, authentication, session startup, and CLI code live in
  separate crates.
- Request handling is isolated from socket handling so it can be tested without
  opening a real socket.

## PAM Authentication

`niralis-auth` provides `PamAuthenticator`, selected by default with:

```toml
[auth]
backend = "pam"
pam_service = "niralis"
```

The PAM service file must be installed manually at `/etc/pam.d/niralis`. An
openSUSE-oriented example is available at `config/pam/niralis`.

The PAM conversation is non-interactive and silent: it supplies the username and
password already received through IPC and does not echo PAM text back to stdout,
stderr, logs, or the client.

The authenticated PAM transaction remains owned by Niralis after
`authenticate()` returns. This preserves the same PAM context for a future
session worker instead of authenticating in one transaction and opening a
session in another.

The password is removed from the PAM conversation immediately after successful
authentication. Niralis does not keep the password alive for the full lifetime
of the authenticated transaction.

`niralisd` does not call `pam::Client::open_session()` directly in this phase.
Future PAM session opening must happen inside an isolated session context so
user environment changes do not contaminate the privileged daemon process.

In phase 4C, the authenticated transaction still remains in the main
`niralisd` process while the worker runs. The PAM transaction is not serialized
or transferred across the worker boundary.

If Niralis later needs one PAM context to own
`pam_authenticate -> pam_acct_mgmt -> pam_open_session -> pam_close_session ->
pam_end`, that authentication flow must move into the worker in a later phase.

## Mock Authentication

`MockAuthenticator` remains available for unit tests and local smoke tests:

- user: `test`
- password: `test`

Use it only with `backend = "mock"`. It is not the default runtime backend.

## Session Worker Boundary

`niralis-session-worker` is a dedicated, ephemeral process created per session
launch attempt when the worker backend is enabled.

The daemon spawns it directly without a shell, with piped stdin/stdout,
inherited stderr, `cwd = /`, and a cleared environment. Workers receive one
internal request, return at most one internal response, and then terminate.

The internal worker protocol is versioned, size-limited, and does not contain
passwords, PAM handles, or other secret material.

Workers that hang are killed and reaped after a timeout; the timeout covers both
waiting for a response and waiting for the worker process to exit after
responding, so no worker can block the login flow indefinitely.

The worker must answer with the same canonical username and `SessionInfo` that
the daemon sent. A worker that returns different session data is treated as a
protocol violation.

When the PAM authenticator is selected, the configured worker binary must come
from a trusted path: no symlink at the worker node, root ownership, and no
group/other write bits on the worker file or its parent directories.

## Mock Session Startup

`niralis-session` can either return success immediately through the mock
launcher or delegate to `niralis-session-worker`, which currently performs only
mock session preparation and returns canonical session data.

Neither launcher calls `setuid`, opens PAM sessions, talks to logind, or
spawns a graphical session in this phase.

## Out of Scope for This Phase

- Greeter process supervision.
- Wayland protocol or UI work.
- Real graphical session spawning.
- `pam_open_session` or `pam_close_session`.
- Passwords or PAM state inside the worker protocol.
- Shutdown or reboot execution.
- Privilege dropping or user switching.
- UID/GID switching, `initgroups`, or logind session creation.
- PAM environment import, `pam_getenvlist`, or user environment application to
  the main daemon.
- `Exec` execution from `.desktop` sessions.
- Real compositor, Wayland, X11, seat, DRM, or VT handling.
- Interactive password prompt in `niralisctl`.
