#!/usr/bin/env bash
# Build the ignored sacrificial-VT harness unprivileged, then execute only its
# already-built libtest binary as root.  It intentionally refuses to coexist
# with any Niralis production state.
set -euo pipefail

die() { printf 'run-vt-integration-test-root: %s\n' "$*" >&2; exit 1; }
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
target_root="$repo_root/target"
uid="$(id -u)"
tests=(
  'launcher::recovery::vt_integration_tests::real_vt_busy_provenance_identifies_exact_holder'
  'launcher::recovery::vt_integration_tests::real_vt_explicit_recovery_after_holder_close_resolves_seat'
)
[[ "$(uname -s)" == Linux && "$uid" != 0 ]] || die 'run as the unprivileged Linux build user'
# The unprivileged build account need not be allowed to open the console.  The
# exact precompiled harness is the only process that opens it, and it runs via
# sudo below.  Still reject a host without the device before compiling.
[[ -c /dev/tty0 && -r /proc/self/stat ]] || die 'VT device and procfs are required'
command -v cargo >/dev/null && command -v python3 >/dev/null && command -v sudo >/dev/null || die 'cargo, python3 and sudo are required'
for exe in /proc/[0-9]*/exe; do
  target="$(readlink "$exe" 2>/dev/null || true)"
  [[ "$target" != */niralis-session-worker && "$target" != */niralisd ]] || die 'a Niralis production process is active'
done
[[ -z "$(find /var/lib/niralis/recovery -maxdepth 1 -type f -name '*.json' -print -quit 2>/dev/null || true)" ]] || die 'a production recovery record exists'
[[ -z "$(systemctl list-units --all --type=scope --no-legend 'niralis-payload-*.scope' 2>/dev/null || true)" ]] || die 'a Niralis payload scope exists'
root_owned="$(find "$repo_root" -xdev -uid 0 -print -quit)"
[[ -z "$root_owned" ]] || die "workspace contains root-owned file: ${root_owned#"$repo_root"/}"

CARGO_TARGET_DIR="$target_root" cargo build -p niralis-session --features vt-integration-tests --bin fixture-vt-holder
helper="$target_root/debug/fixture-vt-holder"
[[ -f "$helper" && -x "$helper" && ! -L "$helper" && "$(stat -c %u "$helper")" == "$uid" ]] || die 'helper validation failed'
helper="$(readlink -f "$helper")"
case "$helper" in "$target_root"/debug/fixture-vt-holder) ;; *) die 'helper outside target';; esac

json="$(mktemp "${TMPDIR:-/tmp}/niralis-vt-test.XXXXXX")"
trap 'rm -f -- "$json"' EXIT
CARGO_TARGET_DIR="$target_root" cargo test -p niralis-session --features vt-integration-tests --lib --no-run --message-format=json >"$json"
harness="$(python3 - "$json" "$target_root" <<'PY'
import json, os, sys
root=os.path.realpath(sys.argv[2]); values=[]
for line in open(sys.argv[1], encoding='utf-8'):
 try: item=json.loads(line)
 except json.JSONDecodeError: continue
 if item.get('reason')=='compiler-artifact' and item.get('target',{}).get('name')=='niralis_session' and 'lib' in item.get('target',{}).get('kind',[]) and item.get('executable'):
  values.append(os.path.realpath(item['executable']))
values=sorted(set(values))
if len(values)!=1: raise SystemExit('expected exactly one lib harness')
path=values[0]
if os.path.islink(path) or not os.path.isfile(path) or not os.access(path,os.X_OK) or os.path.commonpath((root,path))!=root: raise SystemExit('unsafe harness')
print(path)
PY
)"
[[ -f "$harness" && -x "$harness" && ! -L "$harness" && "$(stat -c %u "$harness")" == "$uid" ]] || die 'harness validation failed'
sudo test -r /dev/tty0 -a -r /proc/self/stat || die 'root harness cannot inspect the VT device or procfs'
for test_name in "${tests[@]}"; do
  for iteration in 1 2 3 4 5; do
    sudo env "NIRALIS_VT_FIXTURE_HELPER=$helper" "$harness" "$test_name" --ignored --nocapture --exact
  done
done
root_owned="$(find "$repo_root" -xdev -uid 0 -print -quit)"
[[ -z "$root_owned" ]] || die "root-owned workspace artifact appeared: ${root_owned#"$repo_root"/}"
