# Niralisd Security Notes

Niralis now validates sessions in the daemon, performs PAM only inside the
dedicated `niralis-session-worker`, and introduces a supervised
`niralis-session-child` boundary. Compositor execution and final graphical
session setup remain out of scope.

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
- Session child launches use an explicit trusted executable path and a separate
  versioned, size-limited handshake.

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
3. canonical `PAM_USER` retrieval
4. canonical Unix identity resolution through NSS
5. `open_session()`
6. transaction drop
7. session close and credential cleanup through RAII
8. `pam_end`

In this phase, the worker performs a short PAM lifecycle with a child boundary:

`authenticate -> open_session -> child handshake -> child exit -> close_session -> exit`

The worker remains the owner of the PAM transaction while the child exists. No
compositor or session command is started yet.

## Canonical Unix Identity

After PAM authentication succeeds, the worker uses `PAM_USER` from the PAM
transaction as the authenticated username source of truth.

That post-authentication username is then resolved through NSS using
`getpwnam_r`, not by parsing `/etc/passwd` and not by spawning `getent`.

The resulting `UnixIdentity` contains:

- canonical username
- UID
- primary GID
- home directory
- login shell

Home and shell are preserved as Unix paths without lossy UTF-8 conversion.

If NSS resolution fails after authentication, Niralis treats it as a
post-authentication session failure:

- the PAM session is not opened;
- the rate limiter is not charged as a bad password;
- the daemon returns the generic session-start failure response.

## Canonical Supplementary Groups

After PAM authentication and canonical `UnixIdentity` resolution, the worker
uses `getgrouplist` through NSS with the canonical `pw_name` and primary GID.
The primary GID remains in `UnixIdentity.gid`; the supplementary vector is
sorted, deduplicated, bounded by the system limit, and excludes the primary
GID. A group lookup failure is a post-authentication session failure, so PAM
`open_session` is not called and authentication rate limiting is not charged
as a bad password.

The worker constructs `ResolvedUnixCredentials` before opening the PAM session.
The PAM runtime still does not change the worker process identity: it does not
call `setgroups`, `initgroups`, `setgid`, or `setuid`.

## Privilege Drop Primitive

The privilege-drop primitive is implemented separately for a future dedicated
session child. It pre-validates every UID and GID, explicitly replaces the
inherited supplementary groups, and applies credentials in this irreversible
order:

`setgroups -> setgid -> setuid`

It then verifies real, effective, and saved UIDs and GIDs, plus the observed
supplementary groups. The primary GID is removed from the observed group list
before comparison because Linux does not guarantee whether `getgroups` includes
the effective GID. Verification also bounds the `getgroups` allocation before
using the returned count.

The primitive has a strict architectural precondition: it may run only in a
dedicated, single-threaded session child before user-controlled code. It must
not run in `niralisd` or in the privileged PAM worker that owns the PAM
transaction. A successful mutation followed by a later failure is fatal for
that process; no rollback is attempted.

`AppliedCredentials` confirms the requested Unix UID, GID, and supplementary
group state. It does not prove that Linux capabilities or unusual `securebits`
state are absent. Capability hardening remains a separate requirement before
executing the final graphical session.

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

## Session Child Boundary

After canonical credentials are resolved and `open_session()` succeeds, the
worker starts `niralis-session-child` as a separate executable process. The
child receives only a bounded v2 `ApplyCredentials` handshake containing the
canonical username, session ID, and numeric UID/GID/supplementary groups. It
never receives home, shell, password, PAM handle, transaction, or final
environment.

The child response is bound to the expected canonical username, session ID,
and real spawned PID. The child must exit successfully; invalid responses,
timeouts, and non-zero exits are post-authentication session failures. The
runner kills and reaps the child on failure, and the PAM transaction is dropped
only after the child has terminated.

The entire handshake uses one absolute two-second deadline covering request
write, response read, and child exit. A child that sends a valid `Ready` and
then remains alive is still a timeout. Writer and reader helper threads are
always joined before normal return, and cleanup kills and reaps a live child
before returning an error. The daemon's worker timeout remains an external
defense, not a substitute for this local supervision.

The child rejects UID 0 before any mutation, then applies and verifies
`setgroups -> setgid -> setuid`. It checks real/effective/saved UID and GID
values and supplementary groups before writing `Ready`. The worker compares
the observed applied credentials with its canonical target and logs only the
canonical username, session, PID, UID, primary GID, and group count.

This proves Unix credential state only. It does not prove that capabilities,
securebits, ambient capabilities, inherited privileged file descriptors,
`no_new_privs`, seccomp, namespaces, or LSM state are hardened. No
user-controlled code or compositor is executed yet, so those remain separate
requirements.

The child path is absolute and follows the same root-owned, non-writable trust
policy as the worker. The child performs the real numeric privilege drop but
does not execute a compositor or initialize a desktop session.

## Worker Trust Policy

When PAM is enabled, both the worker and session child binaries must be
trusted before the daemon is allowed to send credentials to the worker.

Required properties:

- absolute path
- real file, not symlink
- executable
- root-owned
- not writable by group or others
- every parent directory is real, root-owned, and not writable by group or
  others

The worker-to-child handshake uses the same no-shell, cleared-environment and
`cwd = /` process policy, but it is a separate internal protocol from the
daemon-to-worker protocol.

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
- runtime application of credential changes by a real session child
- logind integration
- seat, VT, DRM, Wayland, or X11 lifecycle
- PAM environment import back into the daemon
- persistent worker lifetime
- interactive password prompt in `niralisctl`
