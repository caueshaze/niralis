#!/usr/bin/env bash
# Install only the feature-gated physical PreviousBoot smoke harness. This
# script never replaces production Niralis binaries, units, or ledgers.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/install-previous-boot-smoke.sh [--skip-build] [--no-selinux]

Builds niralisd-smoke as the invoking user, then installs only:
  /usr/libexec/niralis-smoke/niralisd-smoke
  /etc/systemd/system/niralisd-smoke@.service
  /var/lib/niralis-smoke

The template unit is installed but never enabled or started by this script.
EOF
}

die() {
    printf 'install-previous-boot-smoke: %s\n' "$*" >&2
    exit 1
}

build=true
install_selinux=true
while (($#)); do
    case "$1" in
        --skip-build) build=false ;;
        --no-selinux) install_selinux=false ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
done

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"
[[ -f Cargo.toml && -d crates ]] || die "not a Niralis repository: $repo_root"

if "$build"; then
    cargo build -p niralisd --release --features supervisor-test-fixtures --bin niralisd-smoke
fi

artifact=target/release/niralisd-smoke
[[ -f "$artifact" && -x "$artifact" && ! -L "$artifact" ]] || \
    die "missing regular release artifact: $artifact"

if ((EUID == 0)); then
    root=()
else
    command -v sudo >/dev/null 2>&1 || die 'sudo is required'
    root=(sudo)
fi

"${root[@]}" install -Dm0755 "$artifact" /usr/libexec/niralis-smoke/niralisd-smoke
"${root[@]}" install -Dm0644 systemd/niralisd-smoke@.service /etc/systemd/system/niralisd-smoke@.service
"${root[@]}" install -d -o root -g root -m0700 /var/lib/niralis-smoke

if "$install_selinux"; then
    command -v semodule >/dev/null 2>&1 || die 'semodule is required'
    command -v restorecon >/dev/null 2>&1 || die 'restorecon is required'
    make -C selinux clean all
    "${root[@]}" semodule -i selinux/niralis.pp
    "${root[@]}" restorecon -Rv /usr/libexec/niralis-smoke /var/lib/niralis-smoke
    "${root[@]}" matchpathcon -V /usr/libexec/niralis-smoke/niralisd-smoke /var/lib/niralis-smoke
fi

"${root[@]}" systemctl daemon-reload
printf '%s\n' 'PreviousBoot smoke harness installed; it remains disabled until explicitly armed.'
