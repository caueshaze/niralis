# A3.4.3c reboot and power-loss validation

The fixture harness validates each durable boundary in a fresh child process. It uses
`NIRALIS_PREVIOUS_BOOT_FAILPOINT` and exits with status `86` immediately after the
selected durable write. The next child opens the same recovery directory and resumes
from the journal; it never reuses coordinator memory.

Supported failpoints are:

`before_resolution_intent`, `after_not_replayed`, `after_resolution_intent`,
`after_historical_resolved`, `after_runtime_release_intent`,
`after_runtime_release_confirmed`, `before_unlink`, `after_unlink_before_receipt`,
`after_removal_receipt`, and `before_seat_free`.

Run the deterministic harness with:

```text
cargo test -p niralis-session --lib \
  launcher::recovery::previous_boot_finalization::process_tests::process_restarts_resume_each_previous_boot_failpoint \
  -- --nocapture
```

The harness checks that old operations remain `NotReplayed`, sequences do not regress,
the record remains present until exact removal, a removed record is not recreated, and
`FreePublished` is the final journal stage. Journal/ledger divergence, replaced inodes,
abandoned temporary files, and duplicate journal candidates are rejected and remain
quarantined.

## Hiraeth physical smoke

Run this section only on the Hiraeth host after the automated gate is green. Record the
old and new boot IDs, record sequence, journal stage, and the final Seat Free event.

1. Create one controlled session and stop at each fixture-safe failpoint.
2. Verify the record and journal on disk, then reboot the host normally.
3. Confirm startup performs only historical finalization: no systemd Kill/Unref, process
   signal, `TerminateSession`, VT activation, `VT_DISALLOCATE`, or `TIOCVHANGUP`.
4. Confirm `NotReplayed` entries, exact record removal, and Seat Free as the last event.
5. Repeat with an interruption after `after_historical_resolved` and after
   `after_runtime_release_confirmed`; reboot again and verify resume without replay or
   premature Free.
6. Confirm a new login succeeds only after the final historical completion.

Do not simulate the physical reboot by calling another coordinator function in the same
process. If Hiraeth is unavailable, report the physical smoke as pending rather than
claiming reboot evidence.

## Interrupted physical smoke harness

The clean production smoke above proves the installed daemon, its sockets, and a new
login. The two interrupted reboot cases use the separate `niralisd-smoke` binary so
that no test record is ever placed in `/var/lib/niralis/recovery`.

Install it explicitly, as the normal build user:

```text
./scripts/install-previous-boot-smoke.sh
```

The harness is compiled only with `supervisor-test-fixtures`, uses
`/var/lib/niralis-smoke/<run-id>/`, and runs the same persistent launcher startup as
the daemon without opening IPC or the recovery-admin socket. It refuses a SameBoot
record before the launcher is constructed and rejects `NIRALIS_TEST_BOOT_ID`; the
physical boot identity must come from `/proc/sys/kernel/random/boot_id`.

For `after_historical_resolved`:

```text
./scripts/previous-boot-physical-smoke.sh prepare a343c-historical
./scripts/previous-boot-physical-smoke.sh arm a343c-historical after_historical_resolved
sudo systemctl reboot
```

After reconnecting, verify that `niralisd-smoke@a343c-historical.service` exited with
status 86, that its journal has `RecordResolved`, that the isolated record remains,
and that `FreePublished` is absent. Then disarm only after that exact durable state:

```text
./scripts/previous-boot-physical-smoke.sh disarm a343c-historical
sudo systemctl reboot
```

On the second boot, require `historical_finalization_resumed`, the four seeded
`historical_operation_not_replayed` entries, exact record removal, and
`seat_free_after_historical_completion`. Restore production only after collecting the
evidence:

```text
./scripts/previous-boot-physical-smoke.sh restore a343c-historical
```

Run the same sequence with `after_runtime_release_confirmed` and a new run id. The
scripts never reboot automatically and retain the isolated ledger and journal; no
purge operation is provided.
