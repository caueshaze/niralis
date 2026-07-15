#!/usr/bin/env bash
# Build and install the locally checked-out Niralis tree into its canonical
# development layout.  This intentionally never overwrites /etc/niralis.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/install-local.sh [--install-selinux-policy] [--restart] [--skip-tests]

Builds the release workspace and installs:
  /usr/sbin/niralisd
  /usr/bin/niralisctl
  /usr/libexec/niralis-session-{worker,child,probe}

--install-selinux-policy  Rebuild and install the local Niralis SELinux policy.
--restart                 Restart niralisd after installation. Do not use while
                          a Niralis graphical session is active.
--skip-tests              Skip cargo test --workspace.
EOF
}

install_selinux_policy=false
restart=false
run_tests=true

while (($#)); do
    case "$1" in
        --install-selinux-policy) install_selinux_policy=true ;;
        --restart) restart=true ;;
        --skip-tests) run_tests=false ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if "$run_tests"; then
    cargo test --workspace
fi
cargo build --release --workspace

if ((EUID == 0)); then
    root=()
else
    root=(sudo)
fi

"${root[@]}" install -Dm0755 target/release/niralisd /usr/sbin/niralisd
"${root[@]}" install -Dm0755 target/release/niralisctl /usr/bin/niralisctl
"${root[@]}" install -Dm0755 target/release/niralis-session-worker /usr/libexec/niralis-session-worker
"${root[@]}" install -Dm0755 target/release/niralis-session-child /usr/libexec/niralis-session-child
"${root[@]}" install -Dm0755 target/release/niralis-session-probe /usr/libexec/niralis-session-probe
"${root[@]}" install -Dm0644 systemd/niralisd.service /etc/systemd/system/niralisd.service

if "$install_selinux_policy"; then
    make -C selinux
    "${root[@]}" semodule -i selinux/niralis.pp
    "${root[@]}" python3 selinux/manage_default_contexts.py install
fi

relabel_paths=(
    /usr/libexec/niralis-session-worker
    /usr/libexec/niralis-session-child
    /usr/libexec/niralis-session-probe
)
for daemon_path in /usr/bin/niralisd /usr/sbin/niralisd; do
    [[ -e "$daemon_path" ]] && relabel_paths+=("$daemon_path")
done
"${root[@]}" restorecon -Rv "${relabel_paths[@]}"

"${root[@]}" systemctl daemon-reload

if "$restart"; then
    configured_exec="$("${root[@]}" systemctl show niralisd.service -p ExecStart --value)"
    if [[ "$configured_exec" != *"path=/usr/bin/setpriv "* ]] ||
        [[ "$configured_exec" != *"--inh-caps=-all -- /usr/sbin/niralisd --config /etc/niralis/niralis.toml"* ]]; then
        printf '%s\n' 'not restarting: a systemd drop-in overrides Niralis ExecStart.' >&2
        printf '%s\n' 'expected: /usr/bin/setpriv --inh-caps=-all -- /usr/sbin/niralisd --config /etc/niralis/niralis.toml' >&2
        printf '%s\n' 'inspect:  sudo systemctl cat niralisd.service' >&2
        printf '%s\n' 'remove or update the obsolete ExecStart override, then rerun this command.' >&2
        exit 1
    fi
    if [[ ! -f /etc/niralis/niralis.toml ]]; then
        printf 'not restarting: /etc/niralis/niralis.toml does not exist\n' >&2
        exit 1
    fi
    "${root[@]}" systemctl restart niralisd
fi

printf '%s\n' 'Niralis binaries installed. Run scripts/smoke-installed.sh --ipc for a read-only IPC check.'
