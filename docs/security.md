# Niralisd Security Notes

Niralis now validates sessions in the daemon, performs PAM only inside the
dedicated `niralis-session-worker`, and introduces a supervised
`niralis-session-child` boundary. Compositor execution and final graphical
session setup remain out of scope.

## Current Guarantees

- Passwords are accepted only through local IPC login requests. `niralisctl`
  accepts them through `--password-stdin`, never a command-line argument.
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
- A selected desktop session is resolved into an internal launch specification
  before PAM: the public `SessionInfo` remains metadata-only, while the bound
  internal object retains the canonical `.desktop` source, absolute executable,
  and bounded argv. It is not sent to the worker in this phase and is never
  executed yet.
- Desktop sources in PAM mode must be regular, non-symlink files below a
  configured canonical root, with root-owned, non-group/world-writable file and
  ancestor path components. Duplicate IDs use first configured root, then
  lexical filename order. Session executable symlinks are resolved to a
  canonical absolute executable for distro compatibility.
- Exec is parsed without a shell. Only `%%` is supported (as a literal `%`);
  every other field code fails closed. Resolution uses only the configured
  session search path, never inherited `PATH`; `TryExec` is an availability
  check only and is never spawned. Path validation has an unavoidable TOCTOU
  window until a future fd-based execution design.

### Read-only installed-session smoke

The diagnostic example below validates an installed desktop entry and prints
its canonical launch specification. It does not start PAM, a worker, a
compositor, or any program named by `Exec`:

```sh
cargo run -p niralis-discovery --example resolve-installed-session -- niri
```
- Worker launches are versioned, size-limited, supervised, and shell-free.
- Session child launches use an explicit trusted executable path and a separate
  versioned, size-limited handshake.

## Seat and virtual-terminal lifecycle

The 4G-B worker selects only the trusted internal `seat0` policy and, on Linux
VT-capable systems, allocates one exact virtual terminal through an owned
lease. `XDG_SEAT` and `XDG_VTNR` are added to the PAM environment only from
that lease, before `pam_open_session`; they are never accepted from the public
client or inherited from the worker environment.

The real child receives a single deliberate terminal capability at fixed FD 3.
All other inherited descriptors remain fail-closed. After `setsid()`, the
child acquires the exact terminal with `TIOCSCTTY`, establishes its own
foreground process group, verifies terminal SID/PGID and device identity, and
closes FD 3 before the final strict FD audit. The worker validates logind Seat
and VT properties against the same lease before emitting `Started`.

Normal tests use fake seat/VT leases and never touch `/dev/console`, activate a
VT, wait for an active VT, or disallocate a real console. Any physical VT smoke
must be explicitly enabled in a dedicated test environment; no automatic
restoration of an unrelated previous VT is attempted.

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

The worker now performs a two-phase PAM lifecycle with a long-lived fixture:

`authenticate -> open_session -> child startup proof -> Started -> fixture exit -> close_session -> exit`

The worker remains the owner of the PAM transaction for the entire fixture
lifetime. No compositor or session command is started yet.

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

`niralis-session-worker` is a dedicated process per login attempt and remains
alive until its session fixture exits.

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
child receives only a bounded v5 `ApplyCredentials` handshake containing the
canonical username, session ID, and numeric UID/GID/supplementary groups. It
never receives home, shell, password, PAM handle, transaction, or final
environment.

The child response is bound to the expected canonical username, session ID,
and real spawned PID. A validated startup proof produces `Started`; the child
and worker then remain alive. The worker reaps the child and closes PAM only
after the fixture exits.

The startup handshake uses one absolute two-second deadline covering request
write and startup proof read. The long-lived fixture lifetime is supervised
separately and is not limited by the startup timeout. Writer and reader helper
threads are always joined before ownership transfer, and cleanup kills and
reaps a live child on startup failure.

### Session termination and process-group cleanup

The worker control endpoint is selected by the daemon before the worker starts;
it is never returned by `Started`. The endpoint is created under the trusted
`/run/niralis/worker-control` hierarchy when available, with a private
temporary fallback for unprivileged tests. Each lifecycle also has an opaque
worker ID.

The bounded control protocol binds a termination request to the worker ID,
worker PID, session PID, and validated session PGID. The worker checks Unix
peer credentials before accepting it. The daemon does not close PAM or kill
the worker as the normal termination path.

Normal termination is:

`Running -> Stopping -> SIGTERM(-PGID) -> grace deadline -> optional
SIGKILL(-PGID) -> session leader reap -> PAM close -> worker exit`.

The worker explicitly reaps the session leader because it is the direct child.
Descendants in the same process group receive the group signal and are checked
for immediate disappearance, but they are not individually reaped by the
worker. A descendant that deliberately calls `setsid()` or `setpgid()` can
escape this process-group boundary; stronger containment belongs to future
cgroup/logind integration.

If the worker becomes unresponsive, the daemon enters emergency cleanup using
only the previously validated PGID, applies bounded SIGTERM/SIGKILL cleanup,
then reaps the worker and records a failed emergency lifecycle. This is not
the normal PAM ownership path.

The child rejects UID 0 before any mutation, then applies and verifies
`setgroups -> setgid -> setuid`. It checks real/effective/saved UID and GID
values and supplementary groups before writing `Ready`. The worker compares
the observed applied credentials with its canonical target and logs only the
canonical username, session, PID, UID, primary GID, and group count.

## Post-Drop Isolation Proof

Before writing `Ready`, the child closes inherited file descriptors at or above
3, applies and verifies the Unix credentials, explicitly clears effective,
permitted, inheritable, and ambient capability sets, and audits capabilities,
`securebits`, `no_new_privs`, and surviving descriptors. The proof requires
those active capability sets to be empty, no dangerous `securebits`, and
exactly file descriptors 0, 1, and 2. The worker revalidates the complete proof
before accepting the response.

The capability bounding set is observed and reported but is not emptied. The
`no_new_privs` value is observed but is not changed and may be either value.
This phase does not prove seccomp, namespace isolation, LSM state, or
capability policy beyond the cleared and audited sets. No user-controlled code
or compositor is executed yet, so these remain separate requirements.

The child rejects a non-empty inheritable capability set. Because this phase
does not mutate capability state, the privileged daemon launch environment must
provide an empty inheritable set. The shipped systemd unit enforces this through
the trusted `/usr/bin/setpriv --inh-caps=-all` wrapper. For manual root/PAM
smoke runs, use the same wrapper; the bounding set may remain non-empty.

The child path is absolute and follows the same root-owned, non-writable trust
policy as the worker. The child performs the real numeric privilege drop but
does not execute a compositor or initialize a desktop session.

## Trusted Exec Handoff

The session configuration contains a separately trusted `probe_path`. The
worker passes canonical home, shell, session type, and the probe path through a
bounded byte-safe child protocol v9. After descriptor sanitization, credential
drop, isolation audit, and `setsid()`, the child changes to the canonical HOME,
constructs the explicit graphical environment, and replaces itself with
`niralis-session-probe` using `exec`. A sealed anonymous descriptor carries
only the already validated final execution plan and pending SELinux exec
context to the probe; it is closed before `Ready` is emitted. The probe
preserves the original PID, reaudits credentials and isolation, verifies
SID/PGID, cwd, terminal, and the explicit environment, then emits `Ready`.
Only after the worker validates that post-exec proof and sends `CommitExec`
does the probe apply the pending SELinux context and `exec` the compositor.
The worker keeps ownership of that same PID for the full session lifetime.

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
- application of the final graphical session runtime by the session child
- logind integration
- seat, VT, DRM, Wayland, or X11 lifecycle
- PAM environment import back into the daemon
- persistent worker lifetime
- interactive password prompt in `niralisctl`
