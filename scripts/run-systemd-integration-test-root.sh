#!/usr/bin/env bash
# Run the already-built, ignored real-systemd test as root without ever running
# Cargo with elevated privileges.
set -euo pipefail

die() {
    printf 'run-systemd-integration-test-root: %s\n' "$*" >&2
    exit 1
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
target_root="$repo_root/target"
test_names=(
    'launcher::recovery::systemd_pin::systemd_integration_tests::real_invocation_bound_unit_kill_empties_scope'
    'launcher::recovery::systemd_pin::systemd_integration_tests::real_unknown_scope_is_detected_without_kill'
    'launcher::recovery::systemd_pin::systemd_integration_tests::real_known_scope_matches_durable_invocation_identity'
)
current_uid="$(id -u)"

[[ "$(uname -s)" == Linux ]] || die 'Linux is required'
[[ "$current_uid" != 0 ]] || die 'run this runner as the unprivileged build user'
[[ -r /sys/fs/cgroup/cgroup.controllers ]] || die 'cgroup v2 is required'
command -v cargo >/dev/null || die 'cargo is required'
command -v python3 >/dev/null || die 'python3 is required to parse Cargo JSON safely'
command -v sudo >/dev/null || die 'sudo is required'

systemd_version="$(systemctl --version | awk 'NR == 1 { print $2 }')"
[[ "$systemd_version" =~ ^[0-9]+$ && "$systemd_version" -ge 254 ]] || \
    die 'systemd 254 or newer is required for invocation-bound lookup'

for exe_link in /proc/[0-9]*/exe; do
    exe="$(readlink "$exe_link" 2>/dev/null || true)"
    [[ "$exe" != */niralis-session-worker ]] || die 'a niralis-session-worker is already active'
done

existing_scopes="$(systemctl list-units --all --type=scope --no-legend 'niralis-payload-*.scope' 2>/dev/null || true)"
[[ -z "$existing_scopes" ]] || die 'a Niralis payload scope already exists; refuse to run beside a real session'

root_owned_before="$(find "$repo_root" -xdev -uid 0 -print -quit)"
[[ -z "$root_owned_before" ]] || die 'workspace already contains root-owned files'

mkdir -p -- "$target_root"
CARGO_TARGET_DIR="$target_root" cargo build -p niralis-session \
    --features systemd-integration-tests \
    --bin fixture-systemd-scope-helper

helper_binary="$target_root/debug/fixture-systemd-scope-helper"
[[ -f "$helper_binary" && -x "$helper_binary" && ! -L "$helper_binary" ]] || \
    die 'fixture helper validation failed'
[[ "$(stat -c %u -- "$helper_binary")" == "$current_uid" ]] || \
    die 'fixture helper is not owned by the current build user'
helper_binary="$(readlink -f -- "$helper_binary")"
case "$helper_binary" in
    "$target_root"/debug/fixture-systemd-scope-helper) ;;
    *) die 'fixture helper is outside the repository target directory' ;;
esac

json_file="$(mktemp "${TMPDIR:-/tmp}/niralis-systemd-test.XXXXXX")"
trap 'rm -f -- "$json_file"' EXIT

CARGO_TARGET_DIR="$target_root" cargo test -p niralis-session \
    --features systemd-integration-tests \
    --lib \
    --no-run \
    --message-format=json >"$json_file"

test_binary="$(python3 - "$json_file" "$target_root" <<'PY'
import json
import os
import sys

messages, target_root = sys.argv[1:]
target_root = os.path.realpath(target_root)
candidates = set()
with open(messages, encoding='utf-8') as stream:
    for line in stream:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get('reason') != 'compiler-artifact':
            continue
        target = message.get('target', {})
        executable = message.get('executable')
        # Cargo normalizes the Rust library target name to an underscore even
        # though the package is named `niralis-session`.
        if target.get('name') == 'niralis_session' and executable and 'lib' in target.get('kind', []):
            candidates.add(os.path.realpath(executable))
if len(candidates) != 1:
    raise SystemExit(
        'expected exactly one niralis_session lib test harness; got: '
        + ', '.join(sorted(candidates))
    )
binary = next(iter(candidates))
if os.path.islink(binary) or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
    raise SystemExit('Cargo reported a non-regular or non-executable harness')
real_binary = os.path.realpath(binary)
if os.path.commonpath((target_root, real_binary)) != target_root:
    raise SystemExit('Cargo reported a harness outside the repository target directory')
if not os.path.basename(real_binary).startswith('niralis_session-'):
    raise SystemExit('Cargo reported an unexpected harness name')
print(real_binary)
PY
)"

[[ -f "$test_binary" && -x "$test_binary" && ! -L "$test_binary" ]] || \
    die 'test harness validation failed'
[[ "$(stat -c %u -- "$test_binary")" == "$current_uid" ]] || \
    die 'test harness is not owned by the current build user'
case "$test_binary" in
    "$target_root"/*/deps/niralis_session-*) ;;
    *) die 'test harness is not directly under the repository target directory' ;;
esac

for test_name in "${test_names[@]}"; do
    for iteration in 1 2 3 4 5; do
        sudo env "NIRALIS_SYSTEMD_FIXTURE_HELPER=$helper_binary" "$test_binary" \
            "$test_name" --ignored --nocapture --exact
    done
done

existing_scopes="$(systemctl list-units --all --type=scope --no-legend 'niralis-payload-*.scope' 2>/dev/null || true)"
[[ -z "$existing_scopes" ]] || die 'a sacrificial Niralis payload scope remained after the harness'

root_owned_after="$(find "$repo_root" -xdev -uid 0 -print -quit)"
[[ -z "$root_owned_after" ]] || die 'root-owned files appeared in the workspace'
