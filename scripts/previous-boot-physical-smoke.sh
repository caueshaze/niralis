#!/usr/bin/env bash
# Operate the isolated physical PreviousBoot smoke without ever modifying the
# production recovery ledger. Reboots stay explicit operator actions.
set -euo pipefail

SMOKE_BIN=/usr/libexec/niralis-smoke/niralisd-smoke
SMOKE_ROOT=/var/lib/niralis-smoke

usage() {
    cat <<'EOF'
Usage:
  scripts/previous-boot-physical-smoke.sh prepare <run-id>
  scripts/previous-boot-physical-smoke.sh arm <run-id> <after_historical_resolved|after_runtime_release_confirmed>
  scripts/previous-boot-physical-smoke.sh disarm <run-id>
  scripts/previous-boot-physical-smoke.sh restore <run-id>

prepare seeds only the isolated ledger. arm disables production for the next
boot and enables the smoke unit, but never reboots the machine itself.
restore retains all smoke evidence and restores the production daemon.
EOF
}

die() {
    printf 'previous-boot-physical-smoke: %s\n' "$*" >&2
    exit 1
}

[[ $# -ge 2 ]] || { usage >&2; exit 2; }
command=$1
run_id=$2
stage=${3:-}

[[ "$run_id" =~ ^[a-z0-9][a-z0-9-]{0,47}$ ]] && [[ "$run_id" != *- ]] || \
    die 'run-id must contain only lowercase letters, digits, and internal hyphens'
[[ -x "$SMOKE_BIN" && ! -L "$SMOKE_BIN" ]] || die "missing smoke binary: $SMOKE_BIN"
command -v sudo >/dev/null 2>&1 || die 'sudo is required'

run_root="$SMOKE_ROOT/$run_id"
manifest="$run_root/service-state"

production_records_present() {
    sudo find /var/lib/niralis/recovery -maxdepth 1 -type f -name '*.json' -print -quit | grep -q .
}

case "$command" in
    prepare)
        [[ -z "$stage" ]] || die 'prepare accepts only a run-id'
        sudo systemctl is-active --quiet niralisd.service || die 'niralisd.service must be active'
        sudo systemctl is-enabled --quiet niralisd.service || die 'niralisd.service must be enabled for the reboot smoke'
        ! production_records_present || die 'a production recovery record exists'
        sudo "$SMOKE_BIN" seed "$run_id"
        printf '%s\n' "Seed complete. Next: arm '$run_id' and then reboot explicitly."
        ;;
    arm)
        [[ -n "$stage" ]] || die 'arm requires a failpoint stage'
        sudo systemctl is-active --quiet niralisd.service || die 'niralisd.service must still be active'
        sudo systemctl is-enabled --quiet niralisd.service || die 'niralisd.service must still be enabled'
        sudo "$SMOKE_BIN" arm "$run_id" "$stage"
        sudo install -d -o root -g root -m0700 "$run_root"
        printf 'niralisd_enabled=enabled\n' | sudo tee "$manifest" >/dev/null
        sudo chmod 0600 "$manifest"
        sudo systemctl disable niralisd.service
        sudo systemctl enable "niralisd-smoke@${run_id}.service"
        sudo systemctl daemon-reload
        printf '%s\n' 'Armed. Do not restart services manually; reboot the host explicitly when ready.'
        ;;
    disarm)
        [[ -z "$stage" ]] || die 'disarm accepts only a run-id'
        sudo "$SMOKE_BIN" disarm "$run_id"
        sudo systemctl daemon-reload
        printf '%s\n' 'Disarmed after the durable stage was verified. Reboot the host explicitly to resume.'
        ;;
    restore)
        [[ -z "$stage" ]] || die 'restore accepts only a run-id'
        [[ "$(sudo cat "$manifest")" == 'niralisd_enabled=enabled' ]] || \
            die 'missing or invalid production service-state manifest'
        sudo systemctl disable "niralisd-smoke@${run_id}.service" || true
        sudo systemctl stop "niralisd-smoke@${run_id}.service" || true
        sudo systemctl enable niralisd.service
        sudo systemctl daemon-reload
        sudo systemctl start niralisd.service
        printf '%s\n' 'Production daemon restored. Smoke ledger and journal were retained for inspection.'
        ;;
    *)
        usage >&2
        die "unknown command: $command"
        ;;
esac
