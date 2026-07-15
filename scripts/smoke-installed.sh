#!/usr/bin/env bash
# Verify the installed daemon without authenticating, opening PAM, allocating a
# VT, or launching a graphical session.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/smoke-installed.sh [--socket PATH] [--ipc] [--ipc-user USER]

Checks the installed Niralis layout, systemd service, SELinux labels (dry-run),
and socket. --ipc additionally runs the read-only `niralisctl status` request.
--ipc-user selects its Unix identity and defaults to niralis.
EOF
}

socket=/run/niralis/niralisd.sock
ipc=false
ipc_user=niralis
while (($#)); do
    case "$1" in
        --socket)
            (($# >= 2)) || { printf '%s\n' '--socket needs a path' >&2; exit 2; }
            socket=$2
            shift
            ;;
        --ipc) ipc=true ;;
        --ipc-user)
            (($# >= 2)) || { printf '%s\n' '--ipc-user needs a username' >&2; exit 2; }
            ipc_user=$2
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

for binary in \
    /usr/sbin/niralisd \
    /usr/bin/niralisctl \
    /usr/libexec/niralis-session-worker \
    /usr/libexec/niralis-session-child \
    /usr/libexec/niralis-session-probe; do
    [[ -x "$binary" ]] || { printf 'missing or non-executable: %s\n' "$binary" >&2; exit 1; }
done

systemctl is-active --quiet niralisd || {
    printf '%s\n' 'niralisd is not active' >&2
    exit 1
}

[[ -S "$socket" ]] || { printf 'missing Niralis socket: %s\n' "$socket" >&2; exit 1; }

sudo restorecon -nvv \
    /usr/bin/niralisd \
    /usr/sbin/niralisd \
    /usr/libexec/niralis-session-worker \
    /usr/libexec/niralis-session-child \
    /usr/libexec/niralis-session-probe

if "$ipc"; then
    sudo -u "$ipc_user" /usr/bin/niralisctl --socket "$socket" status
fi

printf '%s\n' 'Installed Niralis smoke checks passed.'
