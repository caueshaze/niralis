# Niralisd Security Notes

This phase preserves the authenticated PAM transaction with RAII while keeping
graphical session startup, greeter management, Wayland UI, privilege
transitions, and full session lifecycle semantics out of scope.

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

## Mock Authentication

`MockAuthenticator` remains available for unit tests and local smoke tests:

- user: `test`
- password: `test`

Use it only with `backend = "mock"`. It is not the default runtime backend.

## Mock Session Startup

`niralis-session` accepts a username and requested session, logs that a session
would be started, and returns success. It does not call `setuid`, open PAM
sessions, talk to logind, or spawn a graphical session in this phase.

## Out of Scope for This Phase

- Greeter process supervision.
- Wayland protocol or UI work.
- Real graphical session spawning.
- `pam_open_session` or `pam_close_session`.
- Shutdown or reboot execution.
- Privilege dropping or user switching.
- UID/GID switching, `initgroups`, or logind session creation.
- Interactive password prompt in `niralisctl`.
