# Recovery administration

This document describes the root-only control plane used after a supervisor
recovery reaches `vt_disallocate_busy`. It is an incident/recovery interface,
not a normal login or greeter API.

## Access boundary

`niralisctl recovery ...` connects only to the local administrative socket:

```text
/run/niralis/recovery-admin/recovery.sock
```

The daemon validates `SO_PEERCRED` and accepts recovery administration only
from UID 0. The public greeter socket does not expose these operations.

## Inspecting a quarantined record

Find the exact record and inspect it without changing state:

```sh
sudo find /var/lib/niralis/recovery -maxdepth 1 -type f -name '*.json' -print
sudo niralisctl recovery inspect-vt --seat seat0 --record-id RECORD_ID
sudo niralisctl recovery inspect-vt --seat seat0 --record-id RECORD_ID --json
```

The output includes the durable sequence, operation ledger, original EBUSY
provenance, and bounded administrative-attempt history. A record is never
selected heuristically: seat, record ID, and sequence are exact inputs.

## Explicit VT retry

There is no startup, timer, background, or holder-disappearance retry. Each
command below authorizes at most one new `VT_DISALLOCATE` call:

```sh
sudo niralisctl recovery retry-vt-disallocate \
  --seat seat0 \
  --record-id RECORD_ID \
  --record-sequence SEQUENCE
```

Before persisting an intent or issuing the ioctl, Niralis revalidates same
boot, quarantine reason, durable payload cleanup, worker/launcher/session
absence, systemd/logind authority, VT foreground state, target identity, and
the recovery boundary. A failed precondition is persisted as `Rejected` when
appropriate and does not issue the ioctl. A crash after a persisted intent is
`Indeterminate`; a later command requires the exact
`--acknowledge-indeterminate ATTEMPT_ID`.

Do not repeat a command after `EBUSY`, `Rejected`, or `Indeterminate` merely
because time passed. Inspect the durable result and resolve the external cause
first.

## Provenance and safety invariants

After `VT_DISALLOCATE` returns `EBUSY`, the daemon collects bounded,
read-only provenance: active VT, target major/minor identity, visible holders,
PID/starttime/UID/FD, optional executable/cgroup metadata, and inspection
failures. Holder identity is revalidated against PID reuse.

- `TargetStillForeground`, `VisibleUserspaceHolder`, and
  `MultipleVisibleUserspaceHolders` are observed facts.
- `KernelBusyUnattributed` means inspection completed without a visible
  userspace holder; it does not claim a kernel cause.
- `InspectionUnavailable` is not evidence that no holder exists. The seat
  remains quarantined and a retry is blocked.

Niralis never kills a holder, closes another process's FD, invokes
`TIOCVHANGUP`/`vhangup`, activates or restores a VT during administrative
recovery, or retries an ioctl automatically.

On a confirmed explicit retry the durable order is:

```text
AdminIntentPersisted
→ VT_DISALLOCATE (once)
→ VtDisallocateConfirmed
→ RecordResolved
→ RuntimeReleaseConfirmed
→ RecordRemoved
→ SeatFree
```

If runtime release fails, the record remains durable and the seat remains
quarantined. The original startup `Failed(errno=16)` is preserved; later
administrative attempts are recorded separately.

## SELinux requirement

On enforcing hosts the Niralis policy must be current. Provenance needs
read-only procfs process-state traversal and metadata needed to identify a VT
holder. Install the policy through the repository build, never by generating a
local `audit2allow` module:

```sh
make -C selinux clean all
sudo semodule -i selinux/niralis.pp
```

An AVC or `InspectionUnavailable` is a fail-closed result: do not retry until
the specific denied read-only observation is understood and the checked-in
policy has been updated.

## Sacrificial-VT validation

The root-only harness is separate from production state and compiles Cargo as
the normal user before running only the precompiled test binary through sudo:

```sh
./scripts/run-vt-integration-test-root.sh
```

It refuses an active Niralis daemon/session, payload scope, production ledger,
unsafe harness/helper, or unavailable VT/procfs. It runs real provenance and
explicit-recovery tests five times each. It never runs `sudo cargo`.
