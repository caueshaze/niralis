# Niralisd Security Notes

Niralis now validates sessions in the daemon, performs PAM only inside the
dedicated `niralis-session-worker`, and keeps graphical session startup,
privilege transitions, compositor execution, and greeter lifecycle out of
scope.

## Current Guarantees

- Passwords are accepted only through local IPC login requests.
- Passwords are never written to logs, worker arguments, worker environment, or
  daemon responses.
- `LoginFailed` remains generic and does not reveal whether rejection came from
  username, password, PAM policy, or rate limit.
- `SessionUnavailable` remains distinct from authentication failure.
- The daemon Unix socket is local-only and created with restricted
  permissions.
- Login rate limiting remains keyed by username and represents authentication
  failures only.
- Sessions are resolved canonically through discovery before any login backend
  is called.
- Worker launches are versioned, size-limited, supervised, and shell-free.

## PAM Authority Migration

When configured with:

```toml
[auth]
backend = "pam"

[session]
launcher = "worker"
```

the main `niralisd` process no longer creates `PamAuthenticator`,
`PamAuthenticatedTransaction`, or `pam::Client` for login attempts.

Instead, the daemon performs:

1. rate limit checks;
2. canonical session validation;
3. worker trust validation;
4. worker supervision.

The full PAM transaction belongs to the worker.

## Same Transaction Lifecycle

Inside `niralis-session-worker`, the same authenticated transaction is used for:

1. `authenticate()`
2. PAM account management performed by the crate
3. `open_session()`
4. transaction drop
5. session close and credential cleanup through RAII
6. `pam_end`

In this phase, the worker performs a short PAM lifecycle only:

`authenticate -> open_session -> close_session -> exit`

No compositor or session command is started yet.

## Secret Transport and Memory Hygiene

The password currently travels only through:

`IPC client -> niralisd -> private worker stdin pipe`

It is never sent through:

- worker argv
- environment variables
- files
- logs
- public IPC responses

Current cleanup points:

- raw daemon IPC line buffer is wrapped in `Zeroizing<String>`;
- handler password is wrapped in `Zeroizing<String>` immediately on entry;
- worker JSON payload serialization uses `Zeroizing<Vec<u8>>`;
- worker raw JSON read buffer uses `Zeroizing<Vec<u8>>`;
- worker protocol secrets use `WorkerSecret`, which redacts `Debug` and does
  not implement `Clone`;
- the PAM conversation clears its stored password after every authenticate
  attempt;
- launcher writer and reader threads are joined before returning, so no
  secret-bearing thread is left behind after login completion or failure.

## Worker Boundary

`niralis-session-worker` is a dedicated, one-shot process per login attempt.

The daemon spawns it directly with:

- absolute path
- no shell
- piped stdin/stdout
- inherited stderr
- `cwd = /`
- cleared environment

The worker protocol is internal, versioned, and capped at `64 KiB`.

The daemon rejects worker responses that do not match the canonical
`username/session` request it sent.

Workers that hang are killed and reaped. The timeout covers:

- request write
- response read
- worker process exit

## Worker Trust Policy

When PAM is enabled, the worker binary must be trusted before the daemon is
allowed to send credentials to it.

Required properties:

- absolute path
- real file, not symlink
- executable
- root-owned
- not writable by group or others
- every parent directory is real, root-owned, and not writable by group or
  others

`auth = "pam"` with `launcher = "mock"` is rejected at daemon startup.

## PAM Crate Limitations

The current implementation relies on `pam = "0.8.0"` high-level client APIs.

Known limitations:

- `authenticate()` already encapsulates PAM authentication and account checks;
- `open_session()` performs credential and environment work inside the worker
  process;
- session close happens through `Client` drop, so close failures are not
  observable through the current API;
- in `pam = "0.8.0"`, `open_session()` can partially succeed before
  `PAM_REINITIALIZE_CRED` fails; in that edge case the crate may not mark the
  session as open for later `Drop` cleanup, so Niralis documents and accepts
  that upstream limitation in this phase;
- internal `open_session()` paths may panic during environment initialization;
  the worker catches unwind panics, but this does not protect builds compiled
  with `panic = "abort"`.

## Mock Modes

These combinations remain supported:

- `auth = "mock", launcher = "mock"`
- `auth = "mock", launcher = "worker"`

Mock credentials remain:

- user: `test`
- password: `test`

## Out of Scope for This Phase

- real graphical session startup
- `.desktop` `Exec` execution
- compositor or `niri-session` launch
- `setuid`, `setgid`, `initgroups`, or supplementary groups
- logind integration
- seat, VT, DRM, Wayland, or X11 lifecycle
- PAM environment import back into the daemon
- persistent worker lifetime
- interactive password prompt in `niralisctl`
