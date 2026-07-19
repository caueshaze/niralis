#!/usr/bin/env bash
# Build and install the locally checked-out Niralis tree into its canonical
# development layout. This script never overwrites /etc/niralis/niralis.toml.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/install-local.sh [options]

Builds and installs the release workspace:
  /usr/sbin/niralisd
  /usr/bin/niralisctl
  /usr/libexec/niralis-session-{worker,child,probe}

Options:
  --pull                    Run git pull --ff-only before validation/build.
                            Refuses a dirty worktree.
  --selinux                 Build and install the local SELinux policy.
  --no-selinux              Do not build, install, or relabel SELinux policy.
  --install-selinux-policy  Compatibility alias for --selinux.
  --skip-tests              Skip cargo test --workspace.
  --skip-format-check       Skip cargo fmt --all -- --check.
  --skip-build              Reuse existing target/release artifacts.
  --restart                 Restart niralisd after installation.
                            Do not use while a graphical session is active.
  --interactive             Ask the options interactively.
  -h, --help                Show this help.

SELinux is not modified unless --selinux is supplied. The persistent ledger
directory is always provisioned as root:root with mode 0700.
EOF
}

die() {
    printf 'install-local: %s\n' "$*" >&2
    exit 1
}

pull=false
install_selinux=false
selinux_option_seen=false
run_tests=true
run_format_check=true
run_build=true
restart=false
interactive=false
arguments_supplied=$#

ask_yes_no() {
    local prompt=$1
    local default=$2
    local answer
    if [[ "$default" == true ]]; then
        read -r -p "$prompt [Y/n] " answer
        answer=${answer:-y}
    else
        read -r -p "$prompt [y/N] " answer
        answer=${answer:-n}
    fi
    [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

interactive_menu() {
    printf '\nNiralis local installer\n\n'
    if ask_yes_no 'Executar git pull --ff-only?' false; then
        pull=true
    fi
    if ask_yes_no 'Instalar/recarregar política SELinux?' false; then
        install_selinux=true
    fi
    if ask_yes_no 'Executar cargo fmt --check?' true; then
        run_format_check=true
    else
        run_format_check=false
    fi
    if ask_yes_no 'Executar cargo test --workspace?' true; then
        run_tests=true
    else
        run_tests=false
    fi
    if ask_yes_no 'Compilar artefatos release?' true; then
        run_build=true
    else
        run_build=false
    fi
    if ask_yes_no 'Reiniciar niralisd agora?' false; then
        restart=true
    fi
    printf '\n'
}

while (($#)); do
    case "$1" in
        --pull) pull=true ;;
        --selinux|--install-selinux-policy)
            [[ "$selinux_option_seen" == false ]] || die "--selinux and --no-selinux are mutually exclusive"
            install_selinux=true
            selinux_option_seen=true
            ;;
        --no-selinux)
            [[ "$selinux_option_seen" == false ]] || die "--selinux and --no-selinux are mutually exclusive"
            install_selinux=false
            selinux_option_seen=true
            ;;
        --skip-tests) run_tests=false ;;
        --skip-format-check) run_format_check=false ;;
        --skip-build) run_build=false ;;
        --restart) restart=true ;;
        --interactive) interactive=true ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
done

if [[ "$interactive" == true ]] ||
    [[ "$arguments_supplied" -eq 0 && -t 0 && -t 1 ]]; then
    interactive_menu
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ ! -f Cargo.toml || ! -d crates ]]; then
    die "not a Niralis repository: $repo_root"
fi

if "$pull"; then
    command -v git >/dev/null 2>&1 || die "git is required by --pull"
    if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        die "refusing --pull with a dirty worktree; commit, stash, or remove local changes first"
    fi
    git pull --ff-only
fi

if "$run_format_check"; then
    cargo fmt --all -- --check
fi

if "$run_tests"; then
    cargo test --workspace
fi

if "$run_build"; then
    cargo build --release --workspace
fi

artifacts=(
    target/release/niralisd
    target/release/niralisctl
    target/release/niralis-session-worker
    target/release/niralis-session-child
    target/release/niralis-session-probe
)
for artifact in "${artifacts[@]}"; do
    [[ -f "$artifact" ]] || die "missing release artifact: $artifact; remove --skip-build or build it first"
    [[ -x "$artifact" ]] || die "release artifact is not executable: $artifact"
done

if ((EUID == 0)); then
    root=()
else
    command -v sudo >/dev/null 2>&1 || die "sudo is required when not running as root"
    root=(sudo)
fi

install_artifact() {
    local source=$1
    local destination=$2
    "${root[@]}" install -Dm0755 "$source" "$destination"
}

install_artifact target/release/niralisd /usr/sbin/niralisd
install_artifact target/release/niralisctl /usr/bin/niralisctl
install_artifact target/release/niralis-session-worker /usr/libexec/niralis-session-worker
install_artifact target/release/niralis-session-child /usr/libexec/niralis-session-child
install_artifact target/release/niralis-session-probe /usr/libexec/niralis-session-probe
"${root[@]}" install -Dm0644 systemd/niralisd.service /etc/systemd/system/niralisd.service

# The persistent ledger tree is provisioned by root before niralisd starts.
# SELinux labels it separately from /run/niralis when --selinux is enabled.
"${root[@]}" install -d -o root -g root -m 0700 /var/lib/niralis/recovery

if "$install_selinux"; then
    command -v semodule >/dev/null 2>&1 || die "semodule is required by --selinux"
    command -v restorecon >/dev/null 2>&1 || die "restorecon is required by --selinux"
    make -C selinux clean all
    "${root[@]}" semodule -i selinux/niralis.pp
    "${root[@]}" python3 selinux/manage_default_contexts.py install
    relabel_paths=(
        /etc/niralis
        /run/niralis
        /var/lib/niralis
        /var/lib/niralis/recovery
        /usr/libexec/niralis-session-worker
        /usr/libexec/niralis-session-child
        /usr/libexec/niralis-session-probe
    )
    for daemon_path in /usr/bin/niralisd /usr/sbin/niralisd; do
        [[ -e "$daemon_path" ]] && relabel_paths+=("$daemon_path")
    done
    "${root[@]}" restorecon -Rv "${relabel_paths[@]}"
else
    printf '%s\n' 'SELinux installation skipped (--no-selinux/default).'
fi

"${root[@]}" systemctl daemon-reload

if "$restart"; then
    if [[ ! -f /etc/niralis/niralis.toml ]]; then
        die "not restarting: /etc/niralis/niralis.toml does not exist"
    fi
    configured_exec="$("${root[@]}" systemctl show niralisd.service -p ExecStart --value)"
    if [[ "$configured_exec" != *"path=/usr/bin/setpriv "* ]] ||
        [[ "$configured_exec" != *"--inh-caps=-all -- /usr/sbin/niralisd --config /etc/niralis/niralis.toml"* ]]; then
        die "not restarting: niralisd.service ExecStart is overridden; inspect with systemctl cat niralisd.service"
    fi
    "${root[@]}" systemctl reset-failed niralisd.service
    "${root[@]}" systemctl restart niralisd.service
fi

printf 'Niralis installation complete.\n'
printf 'Installed worker: %s\n' /usr/libexec/niralis-session-worker
printf 'Ledger directory: %s\n' /var/lib/niralis/recovery
printf 'SELinux: %s\n' "$([[ "$install_selinux" == true ]] && printf enabled || printf skipped)"
if "$restart"; then
    printf '%s\n' 'Service restart requested; inspect with: systemctl status niralisd.service --no-pager -l'
else
    printf '%s\n' 'Service was not restarted. Use --restart only with no active graphical session.'
fi
